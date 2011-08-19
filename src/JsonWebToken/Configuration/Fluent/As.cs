using System;
using System.Collections.Generic;

namespace Jwt4Net.Configuration.Fluent
{
    public static class As
    {
        public static FluentIssuerConfig Issuer(string myIssuerName)
        {
            return new FluentIssuerConfig(myIssuerName);
        }

        public static FluentConsumerConfig Consumer()
        {
            return new FluentConsumerConfig();
        }
    }

    public class FluentConsumerConfig : IConsumerConfig
    {
        private List<IIssuer> _issuers = new List<IIssuer>();

        public FluentConsumerConfig TrustUnsignedTokens()
        {
            AllowUnsignedTokens = true;
            return this;
        }

        public bool AllowUnsignedTokens { get; private set; }

        public IEnumerable<IIssuer> TrustedIssuers
        {
            get { return _issuers; }
        }

        public FluentConsumerConfig TrustSymmetricIssuer(string myIssuerName, string badgerBadgerBadger)
        {
            _issuers.Add(new TrustedIssuer()
                             {
                                 Name = myIssuerName,
                                 SharedSecret = badgerBadgerBadger
                             });
            return this;
        }
    }

    public class TrustedIssuer : IIssuer
    {
        public string Name { get;  set; }

        public string KeyUriPattern { get;  set; }

        public string SharedSecret { get;  set; }
    }
}