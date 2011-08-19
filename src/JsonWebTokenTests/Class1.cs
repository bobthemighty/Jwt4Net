using System;
using Jwt4Net;
using Jwt4Net.Configuration;
using Jwt4Net.Configuration.Fluent;
using Machine.Specifications;
using TinyIoC;

namespace JsonWebTokenTests
{
    public class When_configuring_the_issuer
    {
        Establish context = () => Jwt4NetContainer.Configure(
            As.Issuer("my issuer name")
                .WithSymmetricKey("badger badger badger", SigningAlgorithm.HS384));

        Because we_fetch_config = () => Config = TinyIoCContainer.Current.Resolve<IIssuerConfig>();
        private static IIssuerConfig Config;

        It should_have_the_correct_algorithm = () => Config.IssuerName.ShouldEqual("my issuer name");
        It should_have_the_correct_shared_key = () => Config.Key.KeyValue.ShouldEqual("badger badger badger");
        It should_have_the_right_algorithm = () => Config.Key.Algorithm.ShouldEqual(SigningAlgorithm.HS384);
    }

    public class When_configuring_the_consumer
    {
        Establish context = () => Jwt4NetContainer.Configure(
            As.Issuer("my issuer name")
                .WithSymmetricKey("badger badger badger", SigningAlgorithm.HS384)
            ,
            As.Consumer()
                .TrustUnsignedTokens()
                .TrustSymmetricIssuer("my issuer name", "badger badger badger"));

        Because we_fetch_config = () =>
            {
                Issuer = TinyIoCContainer.Current.Resolve<IIssuerConfig>();
                Consumer = TinyIoCContainer.Current.Resolve<IConsumerConfig>();
            };

        private static IIssuerConfig Issuer;
        private static IConsumerConfig Consumer;

        It should_have_the_correct_algorithm = () => Issuer.IssuerName.ShouldEqual("my issuer name");
        It should_have_the_correct_shared_key = () => Issuer.Key.KeyValue.ShouldEqual("badger badger badger");
        It should_have_the_right_algorithm = () => Issuer.Key.Algorithm.ShouldEqual(SigningAlgorithm.HS384);

        It should_trust_the_issuer =() =>
            Consumer.TrustedIssuers.ShouldContain(
                iss => iss.Name == "my issuer name" && iss.SharedSecret == "badger badger badger");

        It should_trust_unsigned_tokens = () =>
           Consumer.AllowUnsignedTokens.ShouldBeTrue();
    }
}