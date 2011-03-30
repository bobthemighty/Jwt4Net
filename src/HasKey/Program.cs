using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HasKey
{
    class Program
    {
        static void Main(string[] args)
        {
            if(false == CngKey.Exists(args[0], CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
            {
                Console.WriteLine("No machine key found with name "+args[0]);
            }
            else
            {
                Console.WriteLine("opening key");
                var key = CngKey.Open(args[0], CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);
                Console.ReadKey();
                Console.WriteLine("creating dsa");
                var ecdsa = new ECDsaCng(key);
                Console.WriteLine("Key found:");
                Console.WriteLine(ecdsa.ToXmlString(ECKeyXmlFormat.Rfc4050));

            }
        }
    }
}
