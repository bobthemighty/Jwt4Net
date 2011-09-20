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

            CngKey key;
            var finder = new KeyFinder();
            try
            {
                if (finder.Find(Name, out key))
                {
                    key.Delete();
                    Console.WriteLine("Key " + Name + " deleted successfully");
                }

                else
                {
                    return 2;
                }

                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return 3;
            }
            finally
            {
                finder.Dispose();
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
                            {"n=|name=", "The name or unique id of the key to delete. You may provide a partial match.", v => Name = v},
                        };

            _opts.Parse(args);
            if(Name == null && args.Length == 2)
            Name = args[1];
            return this;
        }

        protected string Name { get; set; }
    }
}