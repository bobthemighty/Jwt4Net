using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Configuration;
using Jwt4Net.Configuration.Fluent;
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
                                    Jwt4NetContainer.Configure(With.Default);
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
        protected static void GivenTheKey(string keyname, CngAlgorithm algorithm)
        {
            Key = CngKey.Create(algorithm, keyname, new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                KeyUsage = CngKeyUsages.Signing
            });
        }


        protected static CngKey Key;

        protected static IContainerConfig ConfigureTheContainer()
        {
             var kc = new FakeEccKeyRepository(Key);

            return Jwt4NetContainer.Configure(
                As.Issuer("my issuer").WithCngKey(Key.KeyName, "https://example.org/"),
                As.Consumer().TrustIssuer("my issuer", "https://example.org/"))
                
                .Replace<ICngKeyProvider, FakeEccKeyRepository>(kc)
                .Replace<IEccPublicKeyProvider, FakeEccKeyRepository>(kc);
        }

        Cleanup the_key = () =>
                                      {
                                          if (null != Key)
                                          {
                                              Key.Delete();
                                              Key.Dispose();
                                          }
                                      };
    }

   

    public class When_signing_an_ecc_256_token : EccContext
    {
        private static string keyname = "test-key-" + Guid.NewGuid();

        Establish context = () =>
                   {
                    GivenTheKey(keyname, CngAlgorithm.ECDsaP256);
                    ConfigureTheContainer();
                        

                    Issuer = Jwt4NetContainer.CreateIssuer();
                    Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
                    Consumer = Jwt4NetContainer.CreateConsumer();
                };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();
    }

    public class When_verifying_a_modified_256_token : EccContext
    {
        private static readonly string keyname = "test-key-" + Guid.NewGuid();

        Establish context = () =>
        {
            GivenTheKey(keyname, CngAlgorithm.ECDsaP256);
            ConfigureTheContainer();

            var initialExpiryDate = new UnixTimeStamp(DateTime.Now.AddDays(1));
            var modifiedValue = initialExpiryDate.Value + 10000;

            Issuer = Jwt4NetContainer.CreateIssuer();
            Issuer.Set(KnownClaims.Expiry, initialExpiryDate);
            Consumer = Jwt4NetContainer.CreateConsumer();

            TokenString = Issuer.Sign();
            var parts = TokenString.Split('.');
            var modifiedPayload = parts[1].Base64UrlDecode(Encoding.UTF8).Replace(initialExpiryDate.Value.ToString(), modifiedValue.ToString());

            TokenString = TokenString.Replace(parts[1], modifiedPayload.Base64UrlEncode());
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
        private static readonly string keyname = "test-key-" + Guid.NewGuid();
        Establish context = () =>
        {
            GivenTheKey(keyname, CngAlgorithm.ECDsaP256);

            var kc = new FakeEccKeyRepository(Key);

            Jwt4NetContainer.Configure(
                As.Issuer("I am not a trusted issuer, mate.").WithCngKey(keyname, "https://example.org/"),
                As.Consumer().TrustIssuer("my issuer", "https://example.org/"))
             .Replace<IEccPublicKeyProvider, FakeEccKeyRepository>(kc);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Consumer = Jwt4NetContainer.CreateConsumer();
            TokenString = Issuer.Sign();
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
            GivenTheKey("test-key-" + Guid.NewGuid(), CngAlgorithm.ECDsaP384);
            ConfigureTheContainer();

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
            GivenTheKey("test-key-" + Guid.NewGuid(), CngAlgorithm.ECDsaP384);
            ConfigureTheContainer();

            Issuer = Jwt4NetContainer.CreateIssuer();
            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
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