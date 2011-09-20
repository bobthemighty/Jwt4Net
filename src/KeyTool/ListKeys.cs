using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Security.Cryptography;

namespace KeyTool
{
    [Command("List all keys installed on the system.", "list")]
    public class ListKeys : KeyCommand
    {
        private string _format;

        public int Execute()
        {
            _format = "{0, -25}  {1, -12}  {2, -7}  {3, -10}  {4, -4}";
            Console.WriteLine();
            Console.WriteLine(_format , "Friendly Name", "Unique name", "KeyType", "Algorithm", "KeySize");
            Console.WriteLine();
            foreach(var key in CngProvider.MicrosoftSoftwareKeyStorageProvider.GetKeys(CngKeyOpenOptions.MachineKey))
            {
                string name = key.KeyName;
                if (name.Length > 23)
                    name = name.Substring(0, 20) + "...";
                Console.WriteLine(_format, name, key.UniqueName.Substring(0, 8), key.IsMachineKey ? "Machine" : "User", key.Algorithm, key.KeySize);
            }
            return 0;
        }

        public void WriteHelp(TextWriter stream)
        {
        }

        public KeyCommand FromArgs(string[] args)
        {
            return this;
        }
    }
}