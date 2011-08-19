using System;
using System.Linq;
using Jwt4Net.Configuration;

namespace Jwt4Net.Signing
{
    public interface ISymmetricKeyProvider
    {
        byte[] GetIssuerKey(SigningAlgorithm algorithm);
        byte[] GetConsumerKey(SigningAlgorithm algorithm, string issuer);
    }

    public class ConfigFileSymmetricKeyProvider : ISymmetricKeyProvider
    {
        private readonly IKeyConfig _issuer;
        private readonly IConsumerConfig _consumer;

        public ConfigFileSymmetricKeyProvider(IKeyConfig issuer, IConsumerConfig consumer)
        {
            _issuer = issuer;
            _consumer = consumer;
        }

        public byte[] GetIssuerKey(SigningAlgorithm algorithm)
        {
            return Convert.FromBase64String(_issuer.KeyValue);
        }

        public byte[] GetConsumerKey(SigningAlgorithm algorithm, string issuer)
        {
            return (from trustedIssuer in _consumer.TrustedIssuers
                    where trustedIssuer.Name == issuer
                    select Convert.FromBase64String(trustedIssuer.SharedSecret)).FirstOrDefault();
        }
    }
}