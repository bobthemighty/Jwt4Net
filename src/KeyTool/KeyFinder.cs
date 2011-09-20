using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Security.Cryptography;

namespace KeyTool
{
    public class KeyFinder : IDisposable
    {
        private IEnumerable<CngKey> keys;

        public bool Find(string match, out CngKey key)
        {
            return Find(k => k.KeyName.ToUpper().Contains(match.ToUpper()) || k.UniqueName.ToUpper().Contains(match.ToUpper()), out key);
        }

        public bool Find(string name, string uniqueId, out CngKey key)
        {
            if (string.IsNullOrEmpty(name + uniqueId))
                throw new ArgumentException();
            Func<CngKey, bool> finder;
            if (false == string.IsNullOrEmpty(name))
            {
                Console.WriteLine("Searching for keys named " + name);
                finder = k => k.KeyName.ToUpper().Contains(name.ToUpper());
            }
            else
            {
                Console.WriteLine("Searching for keys with thumbprint " + uniqueId);
                finder = k => k.UniqueName.ToUpper().Contains(uniqueId.ToUpper());
            }

            return Find(finder, out key);
        }

        private bool Find(Func<CngKey, bool> finder, out CngKey key)
        {
            keys = CngProvider.MicrosoftSoftwareKeyStorageProvider.GetKeys().Where(finder);
            switch (keys.Count())
            {
                case 0:
                    Console.WriteLine("Key not found. Use Keytool list to view keys");
                    key = null;
                    return false;
                case 1:
                    key = keys.First();
                    Console.WriteLine("Key found");
                    return true;
                default:
                    ReportAmbiguity(keys);
                    key = null;
                    return false;
            }


        }

        private static void ReportAmbiguity(IEnumerable<CngKey> keys)
        {
            Console.WriteLine("Ambiguous match:");
            Console.WriteLine("Did you mean one of the following?");
            foreach (var k in keys)
            {
                Console.WriteLine(k.KeyName);
                Console.WriteLine("\tUnique name: " + k.UniqueName);
                Console.WriteLine("\tAlgorithm: " + k.Algorithm);
                Console.WriteLine("\tKeysize: " + k.KeySize);
            }
        }

        protected CngKey Result { get; private set; }

        public void Dispose()
        {
            foreach (var k in keys)
                k.Dispose();
        }
    }

}