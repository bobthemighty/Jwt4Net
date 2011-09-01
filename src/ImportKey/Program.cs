using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NDesk.Options;
using System.Linq;
using Security.Cryptography.X509Certificates;

namespace ImportKey
{
    public class ImportOptions
    {
        public string Path { get; set; }
        public string Password { get; set; }
        public IEnumerable<string> GrantAccess { get; set; }
    }

    class Program
    {
        static ImportOptions Options;

        static void Main(string[] args)
        {
            var cert = new X509Certificate2();
            if (false == GetOptions(args))
                return;

            cert.Import(ReadFully(File.OpenRead(Options.Path)), Options.Password, X509KeyStorageFlags.Exportable|X509KeyStorageFlags.MachineKeySet|X509KeyStorageFlags.PersistKeySet);

            var privateKey = cert.GetCngPrivateKey();
            if (null == privateKey)
            {
                Console.WriteLine("No private key found in pfx");
            }

            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            
            store.Add(cert);
            store.Close();

            GrantAccess(privateKey);
        }

        private static bool GetOptions(string[] args)
        {
            
            Options = new ImportOptions();
            var p = new OptionSet()
            {
                {"in=", "The pfx file to import", v => Options.Path = v},
                {"ga|grantaccess=", "A comma-delimited list of users who need read-access to the generated key.", v => Options.GrantAccess = v.Split(',').Select(s => s.Trim())},
                {"pw|password=", "The password set on the pfx.", v => Options.Password = v}
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
            
            if(string.IsNullOrEmpty(Options.Path))
            {
                p.WriteOptionDescriptions(Console.Out);
                return false;
            }

            if(false == File.Exists(Options.Path))
            {
                Console.WriteLine(Options.Path + " not found");
                return false;
            }

            return true;
        }
        

        private static void GrantAccess(CngKey privateKey)
        {
            if (null == Options.GrantAccess)
                return;

            var path = @"C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\Keys\" + privateKey.UniqueName;
            var file = new FileInfo(path);
            var policy = file.GetAccessControl();
            foreach (var principal in Options.GrantAccess)
            {
                var rule = new FileSystemAccessRule(principal, FileSystemRights.ReadAndExecute, InheritanceFlags.None,
                                                    PropagationFlags.NoPropagateInherit, AccessControlType.Allow);
                policy.AddAccessRule(rule);
            }
            file.SetAccessControl(policy);
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
    }
}
