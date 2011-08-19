using System;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Configuration;
using Machine.Specifications;
using TinyIoC;

namespace JsonWebTokenTests
{
    public class When_reading_unsigned_tokens
    {
        Establish context = () =>
            {
                Jwt4NetContainer.Configure();
                TinyIoCContainer.Current.Register<IConsumerConfig>(new FakeConsumerConfig(){ AllowUnsignedTokens = true});

                Consumer = Jwt4NetContainer.CreateConsumer();
                DateString = new UnixTimeStamp(DateTime.UtcNow.AddHours(1)).Value.ToString();
            };

        Because token_is_read = () => Success = Consumer.TryConsume("{'iss': 'jwt4net', 'exp': "+DateString+"}", out The_Token);

        It should_succeed = () => Success.ShouldBeTrue();

        private static ITokenConsumer Consumer;
        private static JsonWebToken The_Token;
        private static bool Success;
        private static string DateString;
    }

    public class When_an_unsigned_token_contains_periods
    {
        Establish context = () =>
        {
            Jwt4NetContainer.Configure();
            TinyIoCContainer.Current.Register<IConsumerConfig>(new FakeConsumerConfig() { 
                AllowUnsignedTokens = true});

            Consumer = Jwt4NetContainer.CreateConsumer();
            DateString = new UnixTimeStamp(DateTime.UtcNow.AddHours(1)).Value.ToString();
        };

        Because token_is_read = () => Success = Consumer.TryConsume("{'iss': 'http://login.example.com', 'exp': " + DateString + "}", out The_Token);

        It should_fail = () => 
            Success.ShouldBeTrue();

        private static ITokenConsumer Consumer;
        private static JsonWebToken The_Token;
        private static bool Success;
        private static string DateString;
    }

    public class When_reading_a_Token
    {
//        Establish token_is = () => Token_String = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
//
//        Because token_is_read = () => Decoded_Token = new TokenReader().Read(Token_String);
//
//        It should_have_the_Correct_Signature = () => Decoded_Token.Signature.ShouldEqual("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".Base64UrlDecode());
//        It should_have_a_header = () => Decoded_Token.Header.ShouldBeOfType<JsonWebTokenHeader>();
//        It should_be_signed_with_hmac256 = () => Decoded_Token.Header.Algorithm.ShouldEqual(SigningAlgorithm.HS256);
//        It should_decode_the_claimset = () => Decoded_Token.Claims.ShouldBeOfType<JsonClaimSet>();
//        It should_have_the_correct_issuer = () => Decoded_Token.Claims.Get(KnownClaims.Issuer).Value.ShouldEqual("joe");
//        private static string Token_String;
//        private static JsonWebToken Decoded_Token;
    }
}
