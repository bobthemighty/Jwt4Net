using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using GenerateKey;
using NDesk.Options;
using Penge;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace KeyTool
{
    [Command("create a new key for use with jwt4net", "gen", "create")]
    internal class GenerateKey : KeyCommand
    {
        private static KeyOptionSet Options;
        private OptionSet _optionSet = new OptionSet
                                           {
                                               {"a|alg=", "The key type to produce\n must be one of rsa, ecc",  (KeyType v) => Options.Algorithm = v },
                                               {"n|name=", "The name this key will be persisted with.", v => Options.KeyName = v},
                                               {"ks|keysize=", "The size of the generated key in bits. \n Must be one of 256, 384, 521. Defaults to 256", (int v) => Options.KeySize = v},
                                               {"ga|grantaccess=", "A comma-delimited list of users who need read-access to the generated key.", v => Options.GrantAccess = v.Split(',').Select(s => s.Trim())},
                                               {"e|export-private", "If present, this flag causes the program to export the public/private key pair as a PFX", v => Options.ExportPrivateKey = true},
                                               {"pw|password=", "A password for protecting private key information, should only be used with the export-private flag", v => Options.Password = v},
                                               {"np|no-persistence", "Do not persist the key on this machine. Useful for generating keys for other environments", v=> Options.DoNotPersist = true}
                                           };
        private void DeleteKey()
        {
            if(Options.DoNotPersist)
            {
                Key.Delete();
                Key.Dispose();
            }
        }

        private void GrantAccess()
        {
            if (null == Options.GrantAccess)
                return;
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Crypto\Keys\", Key.UniqueName);
            var file = new FileInfo(path);
            var policy = file.GetAccessControl();
            foreach(var principal in Options.GrantAccess)
            {
                var rule = new FileSystemAccessRule(principal, FileSystemRights.ReadAndExecute, InheritanceFlags.None,
                                                    PropagationFlags.NoPropagateInherit, AccessControlType.Allow);
                policy.AddAccessRule(rule);
            }
            file.SetAccessControl(policy);
        }

        private void WriteKey()
        {
            WritePublicKey();
            WritePrivateKey();
            Console.WriteLine("Unique name: " + Key.UniqueName);
            Console.WriteLine(new ECDsaCng(Key).ToXmlString(ECKeyXmlFormat.Rfc4050));
        }

        private void WritePublicKey()
        {
            using(var fs = File.OpenWrite(Options.KeyName+".pem"))
            using(var writer = new PemWriter(fs))
            {
                writer.WritePublicKey(Key);
            }
        }

        private void WritePrivateKey()
        {
            if (false == Options.ExportPrivateKey)
                return;

            var creationParams =
                new X509CertificateCreationParameters(new X500DistinguishedName("CN="+Key.KeyName))
                    {
                        CertificateCreationOptions = X509CertificateCreationOptions.None,
                        SignatureAlgorithm = X509CertificateSignatureAlgorithm.ECDsaSha512,
                        TakeOwnershipOfKey = false
                    };

            var cert = Key.CreateSelfSignedCertificate(creationParams);

            byte[] pfx = string.IsNullOrEmpty(Options.Password) ? 
                                                                    cert.Export(X509ContentType.Pfx) : 
                                                                                                         cert.Export(X509ContentType.Pfx, Options.Password);

            using(var fs  = File.OpenWrite(Options.KeyName+".key.pfx"))
            {
                fs.Write(pfx, 0, pfx.Length);
            }
        }

        private void Build()
        {
            if (Options.Algorithm == KeyType.Ecc)
                Key = new EccKeyGenerator(Options).Result ;
            if(Options.Algorithm == KeyType.Rsa)
                Key = CngKey.Create(CngAlgorithm2.Rsa, Options.KeyName);
        }

        public static CngKey Key { get; set; }
    

        public int Execute()
        {
            if(Options.Valid)
            {
                Build();
                GrantAccess();
                WriteKey();
                DeleteKey();

                return 0;
            }
            WriteHelp(Console.Out);
            return 1;
        }

        public void WriteHelp(TextWriter stream)
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            _optionSet.WriteOptionDescriptions(Console.Out);
            stream.WriteLine("Return codes:");
            stream.WriteLine("\t0: success");
            stream.WriteLine("\t1: argument error");
        }

        public KeyCommand FromArgs(string[] args)
        {
            Options = new KeyOptionSet();

            var p = _optionSet;
            try
            {
                p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            return this;
        }
    }
}