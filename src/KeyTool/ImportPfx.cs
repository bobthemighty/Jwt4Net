using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NDesk.Options;
using Security.Cryptography.X509Certificates;

namespace KeyTool
{
    [Command("Imports a key pair from a pfx file", "import")]
    public class ImportPfx : KeyCommand
    {
        private OptionSet _opts;
        private List<string> Principals = new List<string>();

        public ImportPfx()
        {
            _opts = new OptionSet()
                        {
                {"in=", "The pfx file to import", v => Path = v},
                {"ga|grantaccess=", "A comma-delimited list of users who need read-access to the generated key.", v => Principals = v.Split(',').Select(s => s.Trim()).ToList()},
                {"pw|password=", "The password set on the pfx.", v => Password = v}
            };
        }

        protected string Password { get; set; }

        protected string Path { get; set; }

        public int Execute()
        {
            if (false == File.Exists(Path))
            {
                Console.WriteLine("The file " + Path + " could not be located");
                return 1;
            }
            var cert = new X509Certificate2();
            cert.Import(ReadFully(File.OpenRead(Path)), Password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            var privateKey = cert.GetCngPrivateKey();
            if (null == privateKey)
            {
                Console.WriteLine("No private key found in pfx");
                return 2;
            }

            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            store.Add(cert);
            store.Close();

            GrantAccess(privateKey);
            return 0;
        }

        public void WriteHelp(TextWriter stream)
        {
            _opts.WriteOptionDescriptions(stream);
        }

        public KeyCommand FromArgs(string[] args)
        {
            _opts.Parse(args);
            return this;
        }

        public static byte[] ReadFully(Stream stream)
        {
            byte[] buffer = new byte[32768];
            using (MemoryStream ms = new MemoryStream())
            {
                while (true)
                {
                    int read = stream.Read(buffer, 0, buffer.Length);
                    if (read <= 0)
                        return ms.ToArray();
                    ms.Write(buffer, 0, read);
                }
            }
        }

        private void GrantAccess(CngKey privateKey)
        {
            if (false == Principals.Any())
                return;

            var path = @"C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\Keys\" + privateKey.UniqueName;
            var file = new FileInfo(path);
            var policy = file.GetAccessControl();
            foreach (var principal in Principals)
            {
                var rule = new FileSystemAccessRule(principal, FileSystemRights.ReadAndExecute, InheritanceFlags.None,
                                                    PropagationFlags.NoPropagateInherit, AccessControlType.Allow);
                policy.AddAccessRule(rule);
            }
            file.SetAccessControl(policy);
        }
    }

    public class ImportOptions
    {
        public string Password { get; set; }
        public string FilePath { get; set; }
    }
}
