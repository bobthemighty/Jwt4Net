using System;
using System.IO;
using System.Security.Cryptography;
using NDesk.Options;

namespace KeyTool
{
    [Command("Check for the existence of a key", "find", "exists")]
    public class KeyExists : KeyCommand
    {
        private FindOptions Options;

        public int Execute()
        {
            if (!Options.Valid)
            {
                WriteHelp(Console.Out);
                return 1;
            }

            try
            {
                CngKey key;
                var finder = new KeyFinder();
                if(string.IsNullOrEmpty(Options.Anything))
                {
                    if (finder.Find(Options.Name, Options.UniqueId, out key))
                    {
                        Console.WriteLine("Found key " + Options.Name ?? Options.UniqueId);
                        Console.WriteLine("\t algorithm: " + key.Algorithm);
                        Console.WriteLine("\t keysize: " + key.KeySize);
                        Console.WriteLine("\t usages: " + key.KeyUsage);
                        Console.WriteLine("\t uniquename: " + key.UniqueName);
                    }
                }
                else if (finder.Find(Options.Anything, out key))
                {
                    Console.WriteLine("Found key " + Options.Name ?? Options.UniqueId);
                    Console.WriteLine("\t algorithm: " + key.Algorithm);
                    Console.WriteLine("\t keysize: " + key.KeySize);
                    Console.WriteLine("\t usages: " + key.KeyUsage);
                    Console.WriteLine("\t uniquename: " + key.UniqueName);
                }
                
                return 2;
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
            new FindOptions().Write(stream);
            stream.WriteLine("Return codes:");
            stream.WriteLine("\t0: key located");
            stream.WriteLine("\t1: argument error");
            stream.WriteLine("\t2: key not found");
            stream.WriteLine("\t3: exception while opening key");
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
        private CngKeyOpenOptions _keyOpenOptions;
        
        public string Name { get; private set; }

        public FindOptions(string[] args)
            : this()
        {
           
            _opts.Parse(args);
            Valid = (false == string.IsNullOrEmpty(Name) || false == string.IsNullOrEmpty(UniqueId));
            if (false == Valid && args.Length > 1)
            {
                Anything = args[1];
                Valid = true;
            }

        }

        public FindOptions()
        {
            _keyOpenOptions = CngKeyOpenOptions.MachineKey | CngKeyOpenOptions.UserKey;
            _opts = new OptionSet()
                                      {
                                          {"n|name=", "The name of the key to find", v => Name = v},
                                          {"un=|unique-name=", "A partial match for the key's unique name", v => UniqueId = v}
                                       };
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
        }

        public bool Valid { get; private set; }

        public CngKeyOpenOptions KeyOpenOptions
        {
            get {
                return _keyOpenOptions;
            }
            set {
                _keyOpenOptions = value;
            }
        }

        public CngProvider Provider { get; set; }

        public string UniqueId { get; set; }

        public string Anything { get; set; }

        public void Write(TextWriter stream)
        {
           _opts.WriteOptionDescriptions(stream);
        }
    }
}