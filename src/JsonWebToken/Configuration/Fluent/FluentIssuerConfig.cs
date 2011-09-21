using System;
using System.Configuration;
using System.Security.Cryptography;

namespace Jwt4Net.Configuration.Fluent
{
    public class FluentIssuerConfig : IIssuerConfig
    {
        private readonly string _name;
        private FluentKeyConfig _key;

        public FluentIssuerConfig(string name)
        {
            _name = name;
            _key = new FluentKeyConfig();
        }

        public string IssuerName
        {
            get { return _name; }
        }

        public IKeyConfig Key
        {
            get { return _key; }
        }


        internal class FluentKeyConfig : IKeyConfig
        {
            public SigningAlgorithm Algorithm { get;  set; }
            public KeyFormat KeyFormat { get;  set; }
            public string LocalName { get; set; }
            public string RemoteId { get; set; }
            public string RemoteUri { get; set; }
            public bool IsUserKey { get; set; }
            public string KeyValue { get; set; }
        }

        public FluentIssuerConfig WithSymmetricKey(string keyValue, SigningAlgorithm algorithm)
        {
            _key.Algorithm = algorithm;
            _key.KeyValue = keyValue;
            return this;
        }

        public FluentIssuerConfig WithCngKey(string keyName, string httpsFooOrgBarPem)
        {
            _key.LocalName = keyName;
            _key.RemoteUri = httpsFooOrgBarPem;

            if(false == CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey | CngKeyOpenOptions.UserKey))
            {
                throw new ConfigurationErrorsException("The key "+keyName+" could not be found.");
            }

            using(var key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey|CngKeyOpenOptions.UserKey))
            {
                switch (key.Algorithm.Algorithm)
                {
                    case "ECDSA_P256":
                        _key.Algorithm = SigningAlgorithm.ES256;
                        break;
                    case "ECDSA_P384":
                        _key.Algorithm = SigningAlgorithm.ES384;
                        break;
                    case "ECDSA_P521":
                        _key.Algorithm = SigningAlgorithm.ES512;
                        break;
                    case "RSA":
                        switch (key.KeySize)
                        {
                            case 256:
                                _key.Algorithm = SigningAlgorithm.RS256;
                                break;
                            case 384:
                                _key.Algorithm = SigningAlgorithm.RS384;
                                break;
                            case 512:
                                _key.Algorithm = SigningAlgorithm.RS512;
                                break;
                            default:
                                throw new InvalidKeySizeException("Unexpected key length " + key.KeySize +
                                                                  " for algorithm RSA");
                        }
                        break;
                    default:
                        throw new InvalidAlgorithmException("Unexpected algorithm " + key.Algorithm.Algorithm +
                                                            " for key with name " + key.KeyName);
                }
            }
            return this;
        }


    }

    public class InvalidAlgorithmException : Exception
    {
        public InvalidAlgorithmException(string message)
            : base(message)
        {
            
        }
    }

    public class InvalidKeySizeException : Exception
    {
        public InvalidKeySizeException(string message)
            :base(message)
        {
            
        }
    }
}