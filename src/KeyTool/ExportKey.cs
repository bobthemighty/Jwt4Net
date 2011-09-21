using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NDesk.Options;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace KeyTool
{
    [Command("Export a key pair in pfx format", "export")]
    public class ExportKey : KeyCommand
    {
        private string OutputPath;
        private string Name;
        private string Password;
        private OptionSet _opts;

        public ExportKey()
        {
            _opts = new OptionSet
                        {
                            {"out=", "The output file to write.", v => OutputPath = v},
                            {"n=|name=", "The name or unique id of the key to export", v => Name = v},
                            {"pw|password=", "The password for the exported key pair", v => Password = v}
                        };
        }

        public int Execute()
        {
            if(string.IsNullOrEmpty(OutputPath))
            {
                Console.WriteLine("No output file specified/");
                _opts.WriteOptionDescriptions(Console.Error);
                return 1;
            }
            if(string.IsNullOrEmpty(Name))
            {
                Console.WriteLine("No key specified");
                _opts.WriteOptionDescriptions(Console.Error);
                return 1;
            }

            if (false == OutputPath.EndsWith(".pfx", StringComparison.InvariantCultureIgnoreCase))
                OutputPath += ".pfx";

            CngKey key;
            using (var finder = new KeyFinder())
            {
                if (finder.Find(Name, out key))
                {
                    WritePrivateKey(key);
                    return 0;
                }
                return 2;
            }
        }

        public void WriteHelp(TextWriter stream)
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            _opts.WriteOptionDescriptions(Console.Out);
            stream.WriteLine("Return codes:");
            stream.WriteLine("\t0: success");
            stream.WriteLine("\t1: argument error");
            stream.WriteLine("\t2: key not found");
            stream.WriteLine("\t3: exception occurred while exporting");
        }

        public KeyCommand FromArgs(string[] args)
        {
            _opts.Parse(args);
            return this;
        }

        private void WritePrivateKey(CngKey key)
        {
            var creationParams =
                new X509CertificateCreationParameters(new X500DistinguishedName("CN=" + key.KeyName))
                {
                    CertificateCreationOptions = X509CertificateCreationOptions.None,
                    SignatureAlgorithm = X509CertificateSignatureAlgorithm.ECDsaSha512,
                    TakeOwnershipOfKey = false
                };

            var cert = key.CreateSelfSignedCertificate(creationParams);

            byte[] pfx = string.IsNullOrEmpty(Password) ? cert.Export(X509ContentType.Pfx) : cert.Export(X509ContentType.Pfx, Password);

            using (var fs = File.OpenWrite(OutputPath))
            {
                fs.Write(pfx, 0, pfx.Length);
            }
        }
    }
}