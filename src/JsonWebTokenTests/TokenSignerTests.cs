using System;
using Jwt4Net;
using Jwt4Net.Configuration;
using Jwt4Net.Issuer;
using Jwt4Net.Signing;
using Machine.Specifications;
using Microsoft.Practices.ServiceLocation;

namespace JsonWebTokenTests
{
    public class Context
    {
        static Context()
        {
           Jwt4NetContainer.Configure();
        }
    }

    public class MockSymmetricKeyProvider : ISymmetricKeyProvider
    {
        private byte[] _issuerKey;
        private byte[] _consumerKey;

        public byte[] GetIssuerKey(SigningAlgorithm algorithm)
        {
            return _issuerKey;
        }

        public byte[] GetConsumerKey(SigningAlgorithm algorithm, string issuer)
        {
            return _consumerKey;
        }

        public byte[] IssuerKey
        {
            get { return _issuerKey; }
            set { _issuerKey = value; }
        }

        public byte[] ConsumerKey
        {
            get { return _consumerKey; }
            set { _consumerKey = value; }
        }
    }

    
}
