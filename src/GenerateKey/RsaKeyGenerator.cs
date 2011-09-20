using System;
using System.Security.Cryptography;

namespace GenerateKey
{
    internal class RsaKeyGenerator : KeyGenerator
    {
        private readonly KeyOptionSet _options;

        public RsaKeyGenerator(KeyOptionSet options)
        {
            _options = options;
        }


        public CngKey Result
        {
            get { throw new NotImplementedException(); }
        }

        public void Generate()
        {
            throw new NotImplementedException();
        }
    }
}