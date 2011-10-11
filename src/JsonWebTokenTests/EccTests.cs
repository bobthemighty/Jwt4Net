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

namespace JsonWebTokenTests
{
    public abstract class tokenRoundtripContext
    {
        
        protected static ITokenIssuer Issuer;
        protected static ICngKeyProvider KeyContainer;
        protected static JsonWebToken Token;
        protected static ITokenConsumer Consumer;
        protected static string TokenString { get; set; }

    }

    public class EccContext : tokenRoundtripContext
    {
        protected static CngKey GivenTheKey(string keyname, CngAlgorithm algorithm)
        {
            return CngKey.Create(algorithm, keyname, new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                KeyUsage = CngKeyUsages.Signing
            });
        }

        protected static IContainerConfig ConfigureTheContainer(CngKey cngKey)
        {
             var kc = new FakeEccKeyRepository(cngKey);

            return Jwt4NetContainer.Configure(
                As.Issuer("my issuer").WithCngKey(cngKey.KeyName, "https://example.org/"),
                As.Consumer().TrustIssuer("my issuer", "https://example.org/"))
                
                .Replace<ICngKeyProvider, FakeEccKeyRepository>(kc)
                .Replace<IEccPublicKeyProvider, FakeEccKeyRepository>(kc);
        }

        protected static void RemoveKey(string keyname)
        {
            if(CngKey.Exists(keyname, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
            {
                using(var key = CngKey.Open(keyname, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
                {
                    key.Delete();
                }
            }
        }
    }

    public class When_signing_an_ecc_256_token : EccContext
    {
        private static string keyname = "test-key-" + Guid.NewGuid();

        Establish context = () =>
                   {
                    var key = GivenTheKey(keyname, CngAlgorithm.ECDsaP256);
                    ConfigureTheContainer(key);
                        

                    Issuer = Jwt4NetContainer.CreateIssuer();
                    Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
                    Consumer = Jwt4NetContainer.CreateConsumer();
                };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();

        Cleanup the_key = () => RemoveKey(keyname);
    }

    public class When_verifying_a_modified_256_token : EccContext
    {
        private static readonly string keyname = "test-key-" + Guid.NewGuid();
        Establish context = () =>
        {
            var key = GivenTheKey(keyname, CngAlgorithm.ECDsaP256);
            ConfigureTheContainer(key);

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

        Cleanup the_key = () => RemoveKey(keyname);
    }

    public class When_verifying_a_token_from_an_untrusted_issuer : EccContext
    {
        private static readonly string keyname = "test-key-" + Guid.NewGuid();

        Establish context = () =>
        {
            var key = GivenTheKey(keyname, CngAlgorithm.ECDsaP256);
            var kc = new FakeEccKeyRepository(key);

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

        Cleanup the_key = () => RemoveKey(keyname);
    }

    public class When_signing_an_ecc_384_token : EccContext
    {
        private static string keyname = "test-key-" + Guid.NewGuid();

        Establish context = () =>
        {
            var key = GivenTheKey(keyname, CngAlgorithm.ECDsaP384);
            ConfigureTheContainer(key);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
            Consumer = Jwt4NetContainer.CreateConsumer();
        };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();

        Cleanup the_key = () => RemoveKey(keyname);
    }

    public class When_signing_an_ecc_521_token : EccContext
    {
        private static string keyname = "test-key-" + Guid.NewGuid();

        Establish context = () =>
        {
            var key = GivenTheKey(keyname, CngAlgorithm.ECDsaP384);
            ConfigureTheContainer(key);

            Issuer = Jwt4NetContainer.CreateIssuer();
            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
            Consumer = Jwt4NetContainer.CreateConsumer();
        };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();

        Cleanup the_key = () => RemoveKey(keyname);
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
}