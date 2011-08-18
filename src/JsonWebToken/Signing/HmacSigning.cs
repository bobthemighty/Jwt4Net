using System;
using System.Security.Cryptography;
using System.Text;

namespace Jwt4Net.Signing
{
    public class HmacSigning : ITokenSigning, ITokenVerifier
    {
        private readonly ISymmetricKeyProvider _keyProvider;
        private readonly SigningAlgorithm _algorithm;

        public HmacSigning(ISymmetricKeyProvider keyProvider, SigningAlgorithm algorithm)
        {
            _keyProvider = keyProvider;
            _algorithm = algorithm;
        }

        private HMAC GetAlgorithm(SigningAlgorithm algorithm, byte[] key)
        {
            switch(algorithm)
            {
                case SigningAlgorithm.HS256:
                    return new HMACSHA256(key);
                    break;
                case SigningAlgorithm.HS384:
                    return  new HMACSHA384(key);
                    break;
                case SigningAlgorithm.HS512:
                    return new HMACSHA512(key);
                    break;
            }
            throw new NotSupportedException("No signing found for algorithm "+algorithm);
        }

        public byte[] GetSignature(string claimString)
        {
            var signer = GetAlgorithm(_algorithm, _keyProvider.GetIssuerKey(_algorithm));
            var data = Encoding.UTF8.GetBytes(claimString);
            return signer.ComputeHash(data);
        }

        public bool Verify(JsonWebToken token)
        {
            var issuer = token.Claims.Get(KnownClaims.Issuer).Value;
            var verifier = GetAlgorithm(_algorithm, _keyProvider.GetConsumerKey(_algorithm, issuer));

            var expectedHash = verifier.ComputeHash(token.Payload);
            return CompareSignatures(token.Signature, expectedHash);
        }

        private bool CompareSignatures(byte[] signature, byte[] expectedHash)
        {
            byte? expected;
            byte actual;

            var isValid = signature.Length == expectedHash.Length;

            for(var i = 0; i< signature.Length; i++)
            {
                actual = signature[i];

                if (i < expectedHash.Length)
                    expected = expectedHash[i];
                else
                    expected = null;

                isValid &= (actual == expected);
            }

            return isValid;
        }
    }
}