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
        private byte[] _key;

        public byte[] GetKey(SigningAlgorithm algorithm)
        {
            return _key;
        }
    }

    
}
