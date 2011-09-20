using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using NDesk.Options;

namespace KeyTool
{
    [Command("Grant key access to a named principal.", "grant", "ga")]
    public class GrantAccess : KeyCommand
    {
        private List<string> Principals;
        private string Name;
        private OptionSet _opts;

        public GrantAccess()
        {
            _opts = new OptionSet
                        {
                            {"n|name=", "The name of the key to grant access for", v => Name = v},
                            { "ga|grantaccess=", "A comma-delimited list of users who need read-access to the key.", v => Principals = v.Split(',').Select(s => s.Trim()).ToList()},
                        };
        }

        public int Execute()
        {
            if(string.IsNullOrEmpty(Name))
            {
                Console.WriteLine("Key name must be specified");
                return 1;
            }
            if(!Principals.Any())
            {
                Console.WriteLine("No usernames were provided");
                return 1;
            }

            if(false == CngKey.Exists(Name, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey|CngKeyOpenOptions.UserKey))
            {
                Console.WriteLine("Key "+Name+" not found");
                return 2;
            }

            try
            {
                using (var key = CngKey.Open(Name, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.UserKey|CngKeyOpenOptions.MachineKey))
                {
                    var path = @"C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\Keys\" + key.UniqueName;
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
                Console.WriteLine("Access granted successfully");
                return 0;
            }
            catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return 3;
                }
        }

      

        public void WriteHelp(TextWriter stream)
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            _opts.WriteOptionDescriptions(stream);
            Console.WriteLine();
            Console.WriteLine("Return codes:");
            Console.WriteLine("\t0: success");
            Console.WriteLine("\t1: argument error");
            Console.WriteLine("\t2: key not found");
            Console.WriteLine("\t3: exception occurred while granting access");
        }

        public KeyCommand FromArgs(string[] args)
        {
            _opts.Parse(args);
            return this;
        }
    }
}
