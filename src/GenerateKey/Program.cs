using System;
using System.Linq;
using System.Security.AccessControl;
using NDesk.Options;
using System.Security.Cryptography;
using System.Configuration;
using System.IO;
using Security.Cryptography;

namespace GenerateKey
{
    class Program
    {
        private static KeyOptionSet Options;

        static void Main(string[] args)
        {
            if(GetArgs(args))
            {
                GenerateKey();
                GrantAccess();
                WriteKey();  
            }
        }

        private static void GrantAccess()
        {
            if (null == Options.GrantAccess)
                return;
            var path = @"C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\Keys\" + Key.UniqueName;
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

        private static void WriteKey()
        {
            WritePublicKey();
            Console.WriteLine("Unique name: "+Key.UniqueName);
            Console.WriteLine(new ECDsaCng(Key).ToXmlString(ECKeyXmlFormat.Rfc4050));
        }

        private static void WritePublicKey()
        {
            using(var fs = File.OpenWrite(Options.KeyName+".xml"))
            using (var sw = new StreamWriter(fs))
            {
                sw.Write(new ECDsaCng(Key).ToXmlString(ECKeyXmlFormat.Rfc4050));
            }
        }

        private static void WritePrivateKey()
        {
            var salt = Convert.FromBase64String(ConfigurationManager.AppSettings["salt"]);
            var pwBytes = new PasswordDeriveBytes(Options.Password, salt);
            var keyBytes = Key.Export(CngKeyBlobFormat.EccPrivateBlob);

            var encryptor = new AesManaged();
            
            encryptor.Key = pwBytes.GetBytes(encryptor.KeySize/8);
            encryptor.IV = pwBytes.GetBytes(encryptor.BlockSize/8);

            string encryptedData;
            using (var ms = new MemoryStream())
            using(var cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(keyBytes, 0, keyBytes.Length);
                cs.FlushFinalBlock();
                encryptedData = Convert.ToBase64String(ms.ToArray());
            }

            using (var fs = File.OpenWrite(Options.KeyName + ".key"))
            using(var sw = new StreamWriter(fs))
            {
                sw.Write(encryptedData);
            }
        }

        private static void GenerateKey()
        {
            if (Options.Algorithm == KeyType.Ecc)
                Key = new EccKeyGenerator(Options).Result ;
            if(Options.Algorithm == KeyType.Rsa)
                Key = CngKey.Create(CngAlgorithm2.Rsa, Options.KeyName);
        }

        private static bool GetArgs(string[] args)
        {
            Options = new KeyOptionSet();
            var p = new OptionSet()
            {
                {"a|alg=", "The key type to produce\n must be one of rsa, ecc",  (KeyType v) => Options.Algorithm = v },
                {"n|name=", "The name this key will be persisted with.", v => Options.KeyName = v},
                {"ks|keysize=", "The size of the generated key in bits. \n Must be one of 256, 384, 521. Defaults to 256", (int v) => Options.KeySize = v},
                {"ga|grantaccess=", "A comma-delimited list of users who need read-access to the generated key.", v => Options.GrantAccess = v.Split(',').Select(s => s.Trim())},
            };
            try
            {
                p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
                p.WriteOptionDescriptions(Console.Out);
                return false;
            }
            var success = (false == string.IsNullOrEmpty(Options.KeyName)
                           && new[] {256, 384, 521}.Contains(Options.KeySize));

            if(false == success)
                p.WriteOptionDescriptions(Console.Out);

            return success;
        }

        public static System.Security.Cryptography.CngKey Key { get; set; }
    }
}
