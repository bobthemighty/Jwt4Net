using System;
using System.IO;
using System.Security.Cryptography;
using NDesk.Options;

namespace KeyTool
{
    [Command("Check for the existence of a key", "find", "exists")]
    public class KeyExists : KeyCommand
    {
        private string[] _args;
        private FindOptions Options;

        public int Execute()
        {
            if (!Options.Valid)
            {
                WriteHelp(Console.Out);
                return 1;
            }

            if (Find())
                return 0;
            return 2;
        }

        private bool Find()
        {
            if (!CngKey.Exists(Options.Name))
            {
                return false;
            }
            
            using (var k = CngKey.Open(Options.Name))
            {
                Console.WriteLine("Found key " + Options.Name);
                Console.WriteLine("\t algorithm: " + k.Algorithm);
                Console.WriteLine("\t keysize: " + k.KeySize);
                Console.WriteLine("\t usages: " + k.KeyUsage);
                Console.WriteLine("\t uniquename: " + k.UniqueName);
            }
            return true;
        }

        public void WriteHelp(TextWriter stream)
        {
            new FindOptions().Write(stream);
        }

        public KeyCommand FromArgs(string[] args)
        {
            Options = new FindOptions(args);
            return this;
        }
    }

    public class FindOptions
    {
        private OptionSet _opts;


        public string Name { get; private set; }

        public FindOptions(string[] args)
            : this()
        {
           
            _opts.Parse(args);
            Valid = (false == string.IsNullOrEmpty(Name));
        }

        public FindOptions()
        {
            _opts = new OptionSet()
                                      {
                                          {"n|name=", "The name of the key to find", v => Name = v},
                                       };
        }

        public bool Valid { get; private set; }

        public void Write(TextWriter stream)
        {
           _opts.WriteOptionDescriptions(stream);
        }
    }
}