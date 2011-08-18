using System;
using System.Text;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Consumer.Signing;
using Jwt4Net.Consumer.Validation;
using Jwt4Net.Signing;
using Machine.Specifications;
using TinyIoC;

namespace JsonWebTokenTests
{
    public class HmacContext : tokenRoundtripContext
    {
        private Establish context = () =>
                                        {
                                            TinyIoCContainer.Current.Register(typeof (ICngKeyProvider),typeof (EmptyKeyContainer));
                                            TinyIoCContainer.Current.Register(typeof (IEccPublicKeyProvider),typeof (EmptyKeyContainer));
                                            TinyIoCContainer.Current.Register(typeof (IRsaPublicKeyProvider),typeof (EmptyKeyContainer));
                                        };

        protected static void UseSecrets(string issuer, string consumer)
        {
            TinyIoCContainer.Current.Register(typeof(ISymmetricKeyProvider), typeof(MockSymmetricKeyProvider), 
                new MockSymmetricKeyProvider
                    {
                        ConsumerKey = Encoding.UTF8.GetBytes(consumer),
                        IssuerKey = Encoding.UTF8.GetBytes(issuer)
                    });
        }
    }

    public class When_the_hmac_keys_are_equal : HmacContext
    {
        Establish context = () =>
                                {
                            ConfigureIssuerKey(
                                k => k.Algorithm = SigningAlgorithm.HS512
                                );
                            UseSecrets("secret", "secret");
                            Issuer = Jwt4NetContainer.CreateIssuer();
                            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
                            Consumer = Jwt4NetContainer.CreateConsumer();
                        };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();
        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue();
    }


    public class When_the_hmac_keys_differ : HmacContext
    {
        Establish context = () =>
        {
            ConfigureIssuerKey(
                k => k.Algorithm = SigningAlgorithm.HS512
                );
            UseSecrets("secret", "I am an incorrect secret");
            Issuer = Jwt4NetContainer.CreateIssuer();
            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
            Consumer = Jwt4NetContainer.CreateConsumer();
        };

        Because a_token_is_generated = () => TokenString = Issuer.Sign();

        It should_fail = () => 
            Consumer.TryConsume(TokenString, out Token).ShouldBeFalse();
        
        It should_have_the_right_failure_reason =
            () => Consumer.FailureReason.ShouldBeOfType<SignatureMustBeValidRule>();
    }
}