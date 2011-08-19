using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Configuration;
using Jwt4Net.Consumer.Signing;
using Jwt4Net.Consumer.Validation;
using Jwt4Net.Signing;
using Machine.Specifications;
using Security.Cryptography;
using TinyIoC;

namespace JsonWebTokenTests
{
    public abstract class tokenRoundtripContext
    {
        private Establish context = () =>
                                {
                                    // use a single well-known key for both encoding and decoding
                                    Jwt4NetContainer.Configure();
                                    TinyIoCContainer.Current.Register(typeof(IIssuerConfig), issuerConfig);
                                    TinyIoCContainer.Current.Register(typeof(IKeyConfig), issuerConfig.Key);
                                    TinyIoCContainer.Current.Register(typeof(IConsumerConfig), new FakeConsumerConfig());
                                };

        protected static ITokenIssuer Issuer;
        protected static ICngKeyProvider KeyContainer;
        private static IIssuerConfig issuerConfig = new FakeIssuerConfig() { Key = new FakeKeyConfig() };
        private static FakeConfig config = new FakeConfig(issuerConfig);
        protected static JsonWebToken Token;
        protected static ITokenConsumer Consumer;
        protected static string TokenString { get; set; }

        protected static void ConfigureIssuerKey(params Action<FakeKeyConfig>[] with)
        {
            foreach (var cfg in with)
            {
                cfg(issuerConfig.Key as FakeKeyConfig);
            }
        }


    }

    public class EccContext : tokenRoundtripContext
    {
        protected static void UseKey(CngKey cngKey)
        {
            KeyContainer = new FakeEccKeyRepository(cngKey);
            TinyIoCContainer.Current.Register(typeof(ICngKeyProvider), typeof(FakeEccKeyRepository), KeyContainer);
            TinyIoCContainer.Current.Register(typeof(IEccPublicKeyProvider), typeof(FakeEccKeyRepository), KeyContainer);
            TinyIoCContainer.Current.Register(typeof(IRsaPublicKeyProvider), typeof(FakeRsaKeyRepository), new FakeRsaKeyRepository(CngKey.Create(CngAlgorithm2.Rsa)));
        }
    }

   

    public class When_signing_an_ecc_256_token : EccContext
    {
        Establish context = () =>
                {
                    CngKey cngKey = CngKey.Create(CngAlgorithm.ECDsaP256);
                    UseKey(cngKey);

                    ConfigureIssuerKey(
                        k => k.Algorithm = SigningAlgorithm.ES256,
                        k => k.RemoteUri = "https://www.example.com/keys/ecc256",
                        k => k.KeyFormat = KeyFormat.Rfc4050);

                    Issuer = Jwt4NetContainer.CreateIssuer();
                    Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
                    Consumer = Jwt4NetContainer.CreateConsumer();
                };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();
    }

    public class When_verifying_a_modified_256_token : EccContext
    {
        Establish context = () =>
        {
            CngKey cngKey = CngKey.Create(CngAlgorithm.ECDsaP256);
            UseKey(cngKey);

            ConfigureIssuerKey(
                k => k.Algorithm = SigningAlgorithm.ES256,
                k => k.RemoteUri = "https://www.example.com/keys/ecc256",
                k => k.KeyFormat = KeyFormat.Rfc4050);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Consumer = Jwt4NetContainer.CreateConsumer();
            TokenString = Issuer.Sign();

            var parts = TokenString.Split('.');
            TokenString = TokenString.Replace(parts[1], "{'iss': 'jwt4net', 'userid':9187}".Base64UrlEncode());
        };

        Because token_is_consumed = () => Result = Consumer.TryConsume(TokenString, out Token);

        It should_yield_null = () => Token.ShouldBeNull();

        It should_return_false = () => Result.ShouldBeFalse();

        It should_have_the_correct_failure_reason =
            () => Consumer.FailureReason.ShouldBeOfType<SignatureMustBeValidRule>();

        protected static bool Result { get; set; }
    }

    public class When_verifying_a_token_from_an_untrusted_issuer : EccContext
    {
        Establish context = () =>
        {
            CngKey cngKey = CngKey.Create(CngAlgorithm.ECDsaP256);
            UseKey(cngKey);

            ConfigureIssuerKey(
                k => k.Algorithm = SigningAlgorithm.ES256,
                k => k.RemoteUri = "https://www.example.com/keys/ecc256",
                k => k.KeyFormat = KeyFormat.Rfc4050);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Consumer = Jwt4NetContainer.CreateConsumer();
            TokenString = Issuer.Sign();

            var parts = TokenString.Split('.');
            TokenString = TokenString.Replace(parts[1], "{'iss': 'this is not a recognised issuer'}".Base64UrlEncode());
        };

        Because token_is_consumed = () => Result = Consumer.TryConsume(TokenString, out Token);

        It should_yield_null = () => Token.ShouldBeNull();

        It should_return_false = () => Result.ShouldBeFalse();

        It should_have_the_correct_failure_reason =
            () => Consumer.FailureReason.ShouldBeOfType<IssuerMustBeTrustedRule>();

        protected static bool Result { get; set; }
    }

    public class When_signing_an_ecc_384_token : EccContext
    {
        Establish context = () =>
        {
            CngKey cngKey = CngKey.Create(CngAlgorithm.ECDsaP384);
            UseKey(cngKey);

            ConfigureIssuerKey(
                k => k.Algorithm = SigningAlgorithm.ES384,
                k => k.RemoteUri = "https://www.example.com/keys/ecc384",
                k => k.KeyFormat = KeyFormat.Rfc4050);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
            Consumer = Jwt4NetContainer.CreateConsumer();
        };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();
    }

    public class When_signing_an_ecc_521_token : EccContext
    {
        Establish context = () =>
        {
            CngKey cngKey = CngKey.Create(CngAlgorithm.ECDsaP521);
            UseKey(cngKey);

            ConfigureIssuerKey(
                k => k.Algorithm = SigningAlgorithm.ES512,
                k => k.RemoteUri = "https://www.example.com/keys/ecc",
                k => k.KeyFormat = KeyFormat.Rfc4050);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Consumer = Jwt4NetContainer.CreateConsumer();
        };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();
    }


public class FakeEccKeyRepository : ICngKeyProvider, IEccPublicKeyProvider
    {
        private readonly CngKey _key;
        private ECDsaCng _public;

        public FakeEccKeyRepository(CngKey key)
        {
            _key = key;
            var xml = new ECDsaCng(_key).ToXmlString(ECKeyXmlFormat.Rfc4050);
            _public = new ECDsaCng();
            _public.FromXmlString(xml, ECKeyXmlFormat.Rfc4050);
        }

        public CngKey GetKey()
        {
            return _key;
        }

        public ECDsaCng LoadRemoteKey(JsonWebTokenHeader header)
        {
            return _public;
        }
    }

    public class EmptyKeyContainer : ICngKeyProvider, IRsaPublicKeyProvider, IEccPublicKeyProvider
    {
        public CngKey GetKey()
        {
            throw new NotImplementedException();
        }

        RSACng IRsaPublicKeyProvider.LoadRemoteKey(JsonWebTokenHeader header)
        {
            throw new NotImplementedException();
        }

        ECDsaCng IEccPublicKeyProvider.LoadRemoteKey(JsonWebTokenHeader header)
        {
            throw new NotImplementedException();
        }
    }

public class FakeRsaKeyRepository :ICngKeyProvider, IRsaPublicKeyProvider
{
    private readonly CngKey _key;
        private RSACng _public;

        public FakeRsaKeyRepository(CngKey key)
        {
            _key = key;
            var xml = new RSACng(key).ToXmlString(false);
            _public = new RSACng();
            _public.FromXmlString(xml);
        }

        public CngKey GetKey()
        {
            return _key;
        }

        public RSACng LoadRemoteKey(JsonWebTokenHeader header)
        {
            return _public;
        } 
}


    public class FakeConfig 
    {
        public FakeConfig(IIssuerConfig cfg)
        {
            Issuer = cfg;
        }
        public IIssuerConfig Issuer
        {
            get;
            set;
        }

        public IConsumerConfig ReaderSettings
        {
            get { return new FakeConsumerConfig(); }
        }
    }

    public class FakeConsumerConfig : IConsumerConfig
    {
        public bool AllowUnsignedTokens
        {
            get; set;
        }

        public IEnumerable<IIssuer> TrustedIssuers
        {
            get
            {
                return new[]
                               {
                                   new TrustedIssuer()
                               };
            }
        }

        public class TrustedIssuer : IIssuer
        {
            public string Name
            {
                get { return "jwt4net"; }
            }

            public string KeyUriPattern
            {
                get { return ".*"; }
            }

            public string SharedSecret
            {
                get { return "secret"; }
            }
        }
    }
        public class FakeIssuerConfig : IIssuerConfig
        {
            public string IssuerName
            {
                get { return "jwt4net"; }
            }

            public IKeyConfig Key
            {
                get;
                set;
            }
        }

        public class FakeKeyConfig : IKeyConfig
        {
            public SigningAlgorithm Algorithm { get; set; }
            public KeyFormat KeyFormat { get; set; }
            public string LocalName { get; set; }
            public string RemoteId { get; set; }
            public string RemoteUri { get; set; }
            public bool IsUserKey { get; set; }
            public string KeyValue { get; set; }
        }
    
}