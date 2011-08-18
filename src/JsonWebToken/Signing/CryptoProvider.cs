using System;
using Jwt4Net.Configuration;
using Jwt4Net.Consumer.Signing;
using Jwt4Net.Issuer;

namespace Jwt4Net.Signing
{
    public class CryptoProvider : ICryptoProvider
    {
        private readonly ISymmetricKeyProvider _keyProvider;
        private readonly IConsumerConfig _consumerConfig;
        private readonly ICngKeyProvider _cngKeyProvider;
        private readonly IEccPublicKeyProvider _eccPublicKeyProvider;
        private readonly IRsaPublicKeyProvider _rsaPublicKeyProvider;

        public CryptoProvider(ISymmetricKeyProvider keyProvider, IIssuerConfig issuerConfig, IConsumerConfig consumerConfig, ICngKeyProvider cngKeyProvider, IEccPublicKeyProvider eccPublicKeyProvider, IRsaPublicKeyProvider rsaPublicKeyProvider)
        {
            this.issuerConfig = issuerConfig;
            _keyProvider = keyProvider;
            _consumerConfig = consumerConfig;
            _cngKeyProvider = cngKeyProvider;
            _eccPublicKeyProvider = eccPublicKeyProvider;
            _rsaPublicKeyProvider = rsaPublicKeyProvider;
        }

        public ITokenSigning GetSigner()
        {
            return GetAlgorithm(issuerConfig.Key.Algorithm);
        }

        private ITokenSigning GetAlgorithm(SigningAlgorithm signingAlgorithm)
        {
            switch (signingAlgorithm)
            {
                case SigningAlgorithm.HS256:
                case SigningAlgorithm.HS384:
                case SigningAlgorithm.HS512:
                    return new HmacSigning(_keyProvider, signingAlgorithm);
                case SigningAlgorithm.RS256:
                case SigningAlgorithm.RS384:
                case SigningAlgorithm.RS512:
                    return new RsaSigning(_cngKeyProvider);
                case SigningAlgorithm.ES256:
                case SigningAlgorithm.ES384:
                case SigningAlgorithm.ES512:
                    return new EcdsaCngSigning(_cngKeyProvider);
            }
            throw new NotSupportedException("No implementation found for algorithm " + signingAlgorithm);
        }

        public ITokenVerifier GetSignatureVerification(JsonWebTokenHeader header)
        {
            if (null == header)
                return new NullVerification(_consumerConfig);
            switch (header.Algorithm)
            {
                case SigningAlgorithm.HS256:
                case SigningAlgorithm.HS384:
                case SigningAlgorithm.HS512:
                    return new HmacSigning(_keyProvider, header.Algorithm);
                case SigningAlgorithm.RS256:
                case SigningAlgorithm.RS384:
                case SigningAlgorithm.RS512:
                    return new RsaValidation(_rsaPublicKeyProvider);
                case SigningAlgorithm.ES256:
                case SigningAlgorithm.ES384:
                case SigningAlgorithm.ES512:
                    return new EccValidation(_eccPublicKeyProvider);
            }
            throw new NotImplementedException();
        }

        protected IIssuerConfig issuerConfig { get; set; }
    }

    public class RsaValidation : ITokenVerifier
    {
        private readonly IRsaPublicKeyProvider _keyProvider;

        public RsaValidation(IRsaPublicKeyProvider keyProvider)
        {
            _keyProvider = keyProvider;
        }
        public bool Verify(JsonWebToken token)
        {
            var dsa = _keyProvider.LoadRemoteKey(token.Header);
            var data = token.Payload;
            var signature = token.Signature;
            return dsa.VerifyData(data, signature);
        }
    }

    public class NullVerification : ITokenVerifier
    {
        private readonly IConsumerConfig _consumerConfig;

        public NullVerification(IConsumerConfig consumerConfig)
        {
            _consumerConfig = consumerConfig;
        }

        public bool Verify(JsonWebToken token)
        {
            if (false == _consumerConfig.AllowUnsignedTokens)
                return false;
            return true;
        }
    }

    public interface ITokenSigning
    {
        byte[] GetSignature(string token);
    }

    public interface ITokenVerifier
    {
        bool Verify(JsonWebToken token);
    }

    public interface ICryptoProvider
    {
        ITokenSigning GetSigner();
        ITokenVerifier GetSignatureVerification(JsonWebTokenHeader header);
    }
}
