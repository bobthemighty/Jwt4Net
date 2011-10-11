using System;
using JsonWebTokenTests;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Configuration.Fluent;
using Jwt4Net.Consumer.Validation;
using Jwt4Net.Signing;
using Machine.Specifications;

namespace JsonWebTokenTests
{
    public class HmacContext
    {
        protected static ITokenIssuer Issuer;
        protected static ITokenConsumer Consumer;
        protected static string TokenString;
        protected static JsonWebToken Token;
    }

    public class When_the_hmac_keys_are_equal : HmacContext
    {
        Establish context = () =>
            {
                Jwt4NetContainer.Configure(
                    As.Consumer().TrustSymmetricIssuer("issuer", "secret".Base64Encode()),
                    As.Issuer("issuer").WithSymmetricKey("secret".Base64Encode(), SigningAlgorithm.HS512)
                    );
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
            Jwt4NetContainer.Configure(
                    As.Consumer().TrustSymmetricIssuer("issuer", "KEY A".Base64Encode()),
                    As.Issuer("issuer").WithSymmetricKey("KEY B".Base64Encode(), SigningAlgorithm.HS512)
                    );
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