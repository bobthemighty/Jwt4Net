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
        private List<Type> _ignoredRules = new List<Type>();
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

        public FluentConsumerConfig IgnoringRule<T>()
        {
            _ignoredRules.Add(typeof(T));
            return this;
        }

        public IEnumerable<Type> IgnoredRules
        {
            get { return _ignoredRules; }
        }

        public FluentConsumerConfig TrustIssuer(string myIssuerName, string httpsFooOrg)
        {
            _issuers.Add(new TrustedIssuer()
                             {
                                 KeyUriPattern = httpsFooOrg,
                                 Name = myIssuerName
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