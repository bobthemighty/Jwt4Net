using System;
using System.Security.Cryptography;
using System.Text;

namespace Jwt4Net.Signing
{
    public class HmacSigning : ITokenSigning, ITokenVerifier
    {
        private readonly HMAC _algorithm;

        public HmacSigning(ISymmetricKeyProvider keyProvider, SigningAlgorithm algorithm)
        {
            switch(algorithm)
            {
                case SigningAlgorithm.HS256:
                    _algorithm = new HMACSHA256(keyProvider.GetKey(algorithm));
                    break;
                case SigningAlgorithm.HS384:
                    _algorithm = new HMACSHA384(keyProvider.GetKey(algorithm));
                    break;
                case SigningAlgorithm.HS512:
                    _algorithm = new HMACSHA512(keyProvider.GetKey(algorithm));
                    break;
            }
        }

        public byte[] GetSignature(string claimString)
        {
            var data = Encoding.UTF8.GetBytes(claimString);
            return _algorithm.ComputeHash(data);
        }

        public bool Verify(JsonWebToken token)
        {
            var data = token.Claims.OriginalString.Base64UrlDecode();
            var signature = token.Signature;
            var expectedHash = _algorithm.ComputeHash(data);
            return CompareSignatures(signature, expectedHash);
        }

        private bool CompareSignatures(byte[] signature, byte[] expectedHash)
        {
            throw new NotImplementedException();
        }
    }
}