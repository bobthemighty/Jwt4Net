using System;
using System.IO;
using System.Security.Cryptography;
using NDesk.Options;

namespace KeyTool
{
    [Command("Remove a key from the system", "rm", "delete", "del", "kill")]
    public class DeleteKey : KeyCommand
    {
        private OptionSet _opts;

        public int Execute()
        {
            if (string.IsNullOrEmpty(Name))
            {
                WriteHelp(Console.Error);
                return 1;
            }

            if(false == CngKey.Exists(Name, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey|CngKeyOpenOptions.UserKey))
            {
                Console.WriteLine("Key "+Name+" not found");
                return 2;
            }

            try
            {
                using(var k = CngKey.Open(Name, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey|CngKeyOpenOptions.UserKey))
                {
                    k.Delete();
                }
                Console.WriteLine("Key "+Name+" deleted successfully");
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
            Console.WriteLine("\t3: exception while deleting key");

        }

        public KeyCommand FromArgs(string[] args)
        {
            _opts = new OptionSet
                        {
                            {"n|name=", "The name of the key to delete", v => Name = v}
                        };

            _opts.Parse(args);
            return this;
        }

        protected string Name { get; set; }
    }
}