using System;
using System.Security.Cryptography;
using System.Text;
using Jwt4Net;
using Jwt4Net.Configuration;
using Jwt4Net.Configuration.Fluent;
using Jwt4Net.Consumer.Validation;
using Machine.Specifications;
using Microsoft.Practices.ServiceLocation;
using TinyIoC;

namespace JsonWebTokenTests
{
    public class When_using_the_default_configuration
    {
        Establish context = () =>
                  Jwt4NetContainer.Configure(With.Default);

        Because we_create_a_consumer_and_issuer = () =>
                {
                    Consumer = Jwt4NetContainer.CreateConsumer();
                    Issuer = Jwt4NetContainer.CreateIssuer();
                };

        It should_successfully_roundtrip_a_token = () =>
            {
                JsonWebToken token;
                Issuer.Set(KnownClaims.Expiry, DateTime.Now.AddDays(1));
                Consumer.TryConsume(Issuer.Sign(), out token).ShouldBeTrue();
            };

        private static ITokenConsumer Consumer;
        private static ITokenIssuer Issuer;
    }

    namespace When_using_fluent_configuration_for_hmac
    {
        public class When_configuring_the_consumer
        {
            Establish context = () =>  Jwt4NetContainer.Configure(
                As.Issuer("my issuer name")
                    .WithSymmetricKey(_secretKey, SigningAlgorithm.HS384)
                ,
                As.Consumer()
                    .TrustUnsignedTokens()
                    .TrustSymmetricIssuer("my issuer name", _secretKey));

            Because we_fetch_config = () =>
                {
                    Issuer = ServiceLocator.Current.GetInstance<IIssuerConfig>();
                    Consumer = ServiceLocator.Current.GetInstance<IConsumerConfig>();
                };

            private static IIssuerConfig Issuer;
            private static IConsumerConfig Consumer;

            It should_have_the_correct_algorithm = () => Issuer.IssuerName.ShouldEqual("my issuer name");
            It should_have_the_correct_shared_key = () => Issuer.Key.KeyValue.ShouldEqual(_secretKey);
            It should_have_the_right_algorithm = () => Issuer.Key.Algorithm.ShouldEqual(SigningAlgorithm.HS384);

            It should_trust_the_issuer = () =>
                Consumer.TrustedIssuers.ShouldContain(
                    iss => iss.Name == "my issuer name" && iss.SharedSecret == _secretKey);

            It should_trust_unsigned_tokens = () =>
               Consumer.AllowUnsignedTokens.ShouldBeTrue();


            It should_successfully_roundtrip_a_token = () =>
               {                                               
                JsonWebToken token;
                var issuer = Jwt4NetContainer.CreateIssuer();
                var consumer = Jwt4NetContainer.CreateConsumer();
                issuer.Set(KnownClaims.Expiry, DateTime.Now.AddDays(1));
                consumer.TryConsume(issuer.Sign(), out token).ShouldBeTrue();
            };

            private static string _secretKey = Convert.ToBase64String( Encoding.UTF8.GetBytes("badger badger badger"));
        }

        public class When_removing_rules
        {
            Establish context = () => Jwt4NetContainer.Configure(
               As.Issuer("my issuer name")
                   .WithSymmetricKey(_secretKey, SigningAlgorithm.HS384)
               ,
               As.Consumer()
                   .TrustUnsignedTokens()
                   .TrustSymmetricIssuer("my issuer name", _secretKey)
                   .IgnoringRule<ExpiryDateMustBeInThePastRule>());

            Because we_instantiate_a_consumer_and_issuer = () =>
            {
                Issuer = Jwt4NetContainer.CreateIssuer();
                Consumer = Jwt4NetContainer.CreateConsumer();
            };

            It should_successfully_roundtrip_a_token = () =>
            {
                JsonWebToken token;
                Issuer.Set(KnownClaims.Expiry, DateTime.Now.AddDays(-1));
                Consumer.TryConsume(Issuer.Sign(), out token).ShouldBeTrue();
            };

            private static ITokenIssuer Issuer;
            private static ITokenConsumer Consumer;
            private static string _secretKey = Convert.ToBase64String( Encoding.UTF8.GetBytes("badger badger badger"));
        }

        public class When_configuring_the_issuer
        {
            Establish context = () => Jwt4NetContainer.Configure(
                As.Issuer("my issuer name")
                    .WithSymmetricKey(_sharedKey, SigningAlgorithm.HS384));

            Because we_fetch_config = () => Config = ServiceLocator.Current.GetInstance<IIssuerConfig>();

            It should_have_the_correct_algorithm = () => Config.IssuerName.ShouldEqual("my issuer name");
            It should_have_the_correct_shared_key = () => Config.Key.KeyValue.ShouldEqual(_sharedKey);

            It should_have_the_right_algorithm = () => 
                                                 Config.Key.Algorithm.ShouldEqual(SigningAlgorithm.HS384);

            private static string _sharedKey = Convert.ToBase64String(Encoding.UTF8.GetBytes("badger badger badger"));
            private static IIssuerConfig Config;
        }
    }

    namespace When_using_fluent_configuration_for_ecc
    {
        public class When_configuring_the_consumer
        {
            Establish context = () =>
                                    {
                                        MakeEccKey();
                                        Jwt4NetContainer.Configure(
                                            As.Issuer("my issuer name").WithCngKey(keyName, "https://foo.org/bar.pem"),
                                            
                                            As.Consumer()
                                               .IgnoringRule<SignatureMustBeValidRule>()
                                               .TrustUnsignedTokens()
                                               .TrustIssuer("my issuer name", "https://foo.org/*"));
                                    };

            private static void MakeEccKey()
            {
                keyName = Guid.NewGuid().ToString();
                CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters()
                                                                   {
                                                                       KeyUsage = CngKeyUsages.Signing,
                                                                       KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                                                                       Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
                                                                   });
            }

            Because we_fetch_config = () =>
            {
                Issuer = ServiceLocator.Current.GetInstance<IIssuerConfig>();
                Consumer = ServiceLocator.Current.GetInstance<IConsumerConfig>();
            };

            private static IIssuerConfig Issuer;
            private static IConsumerConfig Consumer;

            It should_have_the_correct_algorithm = () => Issuer.IssuerName.ShouldEqual("my issuer name");
            It should_have_the_correct_shared_key = () => Issuer.Key.LocalName.ShouldEqual(keyName);
            It should_have_the_right_algorithm = () => Issuer.Key.Algorithm.ShouldEqual(SigningAlgorithm.ES256);

            It should_trust_the_issuer = () =>
                Consumer.TrustedIssuers.ShouldContain(
                    iss => iss.Name == "my issuer name" && iss.KeyUriPattern == "https://foo.org/*");

            It should_trust_unsigned_tokens = () =>
               Consumer.AllowUnsignedTokens.ShouldBeTrue();


            It should_successfully_roundtrip_a_token = () =>
            {
                JsonWebToken token;
                var issuer = Jwt4NetContainer.CreateIssuer();
                var consumer = Jwt4NetContainer.CreateConsumer();
                issuer.Set(KnownClaims.Expiry, DateTime.Now.AddDays(1));
                consumer.TryConsume(issuer.Sign(), out token).ShouldBeTrue();
            };

            Cleanup the_key = () =>
            {
                using (var k = CngKey.Open(keyName))
                {
                    k.Delete();
                }
            };


            private static string keyName;
        }

        public class When_configuring_the_issuer
        {
            Establish context = () => Jwt4NetContainer.Configure(
                As.Issuer("my issuer name")
                    .WithSymmetricKey(_sharedKey, SigningAlgorithm.HS384));

            Because we_fetch_config = () => Config = ServiceLocator.Current.GetInstance<IIssuerConfig>();

            It should_have_the_correct_algorithm = () => Config.IssuerName.ShouldEqual("my issuer name");
            It should_have_the_correct_shared_key = () => Config.Key.KeyValue.ShouldEqual(_sharedKey);

            It should_have_the_right_algorithm = () =>
                                                 Config.Key.Algorithm.ShouldEqual(SigningAlgorithm.HS384);

            private static string _sharedKey = Convert.ToBase64String(Encoding.UTF8.GetBytes("badger badger badger"));
            private static IIssuerConfig Config;
        }
    }
}