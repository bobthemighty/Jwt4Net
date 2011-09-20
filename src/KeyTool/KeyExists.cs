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

            try
            {
                if (Find())
                    return 0;
                Console.WriteLine("No key found");
                return 2;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return 3;
            }
        }

        private bool Find()
        {
            if (!CngKey.Exists(Options.Name, Options.Provider, Options.KeyOpenOptions))
            {
                return false;
            }
            
            using (var k = CngKey.Open(Options.Name, Options.Provider, Options.KeyOpenOptions))
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
            Valid = (false == string.IsNullOrEmpty(Name));
        }

        public FindOptions()
        {
            _keyOpenOptions = CngKeyOpenOptions.MachineKey | CngKeyOpenOptions.UserKey;
            _opts = new OptionSet()
                                      {
                                          {"n|name=", "The name of the key to find", v => Name = v},
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

        public void Write(TextWriter stream)
        {
           _opts.WriteOptionDescriptions(stream);
        }
    }
}