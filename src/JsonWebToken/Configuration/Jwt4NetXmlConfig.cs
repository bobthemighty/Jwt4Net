using System;
using System.Collections.Generic;
using System.Configuration;
using Jwt4Net.Signing;

namespace Jwt4Net.Configuration
{
    public class Jwt4NetXmlConfig : ConfigurationSection
    {
        public IIssuerConfig Issuer
        {
            get { return _Issuer; }
        }

        public IConsumerConfig ReaderSettings
        {
            get { return _Reader; }
        }

        [ConfigurationProperty("issuer", IsRequired = false)]
        private IssuerConfig _Issuer
        {
            get { return this["issuer"] as IssuerConfig; }
        }

        [ConfigurationProperty("consumer", IsRequired = false)]
        private ConsumerConfig _Reader
        {
            get { return this["consumer"] as ConsumerConfig; }
        }

        internal class IssuerConfig : ConfigurationElement, IIssuerConfig
        {
            [ConfigurationProperty("name", IsRequired = true)]
            public string IssuerName
            {
                get { return (string)this["name"]; }
            }

            public IKeyConfig Key
            {
                get { return _Key; }
            }

            [ConfigurationProperty("key", IsRequired = true)]
            private KeyConfig _Key
            {
                get { return (KeyConfig)this["key"]; }
            }
        }

        internal class ConsumerConfig : ConfigurationElement, IConsumerConfig
        {
            [ConfigurationProperty("allowUnsignedTokens", IsRequired = false, DefaultValue = false)]
            public bool AllowUnsignedTokens
            {
                get { return (bool)this["allowUnsignedTokens"]; }
            }

            
            public IEnumerable<IIssuer> TrustedIssuers
            {
                get
                {
                    if (null == TrustedIssuersElement)
                        yield break;
                    foreach (var el in TrustedIssuersElement)
                        yield return (el as TrustedIssuer);
                }
            }

            [ConfigurationProperty("trustedIssuers", IsRequired = false)]
            private TrustedIssuersElement TrustedIssuersElement
            {
                get
                {
                    return (TrustedIssuersElement) this["trustedIssuers"];
                }
            }
        }

        internal class TrustedIssuersElement : ConfigurationElementCollection
        {
            protected override ConfigurationElement CreateNewElement()
            {
                return new TrustedIssuer();
            }

            protected override object GetElementKey(ConfigurationElement element)
            {
                return ((TrustedIssuer)element).Name;
            }
        }

        internal class TrustedIssuer : ConfigurationElement, IIssuer
        {
            [ConfigurationProperty("name", IsKey = true, IsRequired = true)]
            public string Name
            {
                get
                {
                    return (string)this["name"];
                }
            }

            [ConfigurationProperty("keyUriPattern", IsKey = true, IsRequired = false)]
            public string KeyUriPattern
            {
                get
                {
                    return (string)this["keyUriPattern"];
                }
            }

            public string SharedSecret
            {
                get { return (string) this["keyValue"]; }
            }
        }

        public class KeyConfig : ConfigurationElement, IKeyConfig
        {
            [ConfigurationProperty("localName", IsRequired = true)]
            public string LocalName
            {
                get
                {
                    return ((string)this["localName"]).Replace("{MachineName}", Environment.MachineName);
                }
            }

            [ConfigurationProperty("remoteId", IsRequired = false)]
            public string RemoteId
            {
                get
                { return (string)this["remoteId"]; }
            }

            [ConfigurationProperty("remoteUri", IsRequired = true)]
            public string RemoteUri
            {
                get
                {
                    return ((string)this["remoteUri"]).Replace("{MachineName}", Environment.MachineName);
                }
            }

            [ConfigurationProperty("isUserKey", IsRequired = false, DefaultValue = false)]
            public bool IsUserKey
            {
                get { return (bool)this["isUserKey"]; }
            }

            [ConfigurationProperty("keyValue", DefaultValue = new byte[0], IsRequired = false)]
            public byte[] KeyValue
            {
                get { return ((string)this["KeyValue"]).Base64UrlDecode(); }
            }

            [ConfigurationProperty("format", IsRequired = true)]
            public KeyFormat KeyFormat
            {
                get
                {
                    return (KeyFormat)this["format"];
                }
            }

            [ConfigurationProperty("algorithm", IsRequired = true)]
            public SigningAlgorithm Algorithm
            {
                get
                {
                    return (SigningAlgorithm)this["algorithm"];
                }
            }
        }
    }

    public interface IIssuer
    {
        string Name { get; }
        string KeyUriPattern { get; }
        string SharedSecret { get; }
    }
}