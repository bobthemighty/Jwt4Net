using System;
using System.Security.Cryptography;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Consumer.Validation;
using Jwt4Net.Signing;
using Machine.Specifications;
using Security.Cryptography;

namespace JsonWebTokenTests
{
//    public class RsaContext : tokenRoundtripContext
//    {
//    }
//
//    public class When_signing_an_rsa_256_token : RsaContext
//    {
//        Establish context = () =>
//        {
//            GivenTheKey("test-key-"+Guid.NewGuid(), CngAlgorithm2.Rsa);
//            ConfigureTheContainer();
//
//
//            Issuer = Jwt4NetContainer.CreateIssuer();
//            Issuer.Set(KnownClaims.Expiry, new UnixTimeStamp(DateTime.Now.AddDays(1)));
//            Consumer = Jwt4NetContainer.CreateConsumer();
//        };
//
//        Because a_token_is_generated = () => TokenString = Issuer.Sign();
//        It should_be_readable = () => Consumer.TryConsume(TokenString, out Token).ShouldBeTrue(); 
//    }
//
//    public class When_verifying_a_modified_RS256_token : RsaContext
//    {
//        Establish context = () =>
//        {
//            CngKey cngKey = CngKey.Create(CngAlgorithm2.Rsa);
//            UseKey(cngKey);
//
//            ConfigureIssuerKey(
//                k => k.Algorithm = SigningAlgorithm.RS256,
//                k => k.RemoteUri = "https://www.example.com/keys/rsa256",
//                k => k.KeyFormat = KeyFormat.Rfc4050);
//
//            Issuer = Jwt4NetContainer.CreateIssuer();
//            Consumer = Jwt4NetContainer.CreateConsumer();
//            TokenString = Issuer.Sign();
//
//            var parts = TokenString.Split('.');
//            TokenString = TokenString.Replace(parts[1], "{'iss': 'jwt4net', 'userid':9187}".Base64UrlEncode());
//        };
//
//        Because token_is_consumed = () => Result = Consumer.TryConsume(TokenString, out Token);
//
//        It should_yield_null = () => Token.ShouldBeNull();
//
//        It should_return_false = () => Result.ShouldBeFalse();
//
//        It should_have_the_correct_failure_reason =
//            () => Consumer.FailureReason.ShouldBeOfType<SignatureMustBeValidRule>();
//
//        protected static bool Result { get; set; }
//    }
}