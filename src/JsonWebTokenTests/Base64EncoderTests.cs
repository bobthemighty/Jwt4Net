using System;
using System.Text;
using Jwt4Net;
using Jwt4Net.Claims;
using Jwt4Net.Signing;
using Machine.Specifications;

namespace JsonWebTokenTests
{
    public class When_encoding_a_string
    {
       It should_encode_as_expected = () =>
            unencodedClaimSegment.Base64UrlEncode().ShouldEqual(encodedClaimSegment);

       It should_decode_correctly = () =>
            encodedClaimSegment.Base64UrlDecode(Encoding.UTF8).ShouldEqual(unencodedClaimSegment);

        private static string encodedClaimSegment =
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        private static ClaimDescriptor<bool> IsRoot = new ClaimDescriptor<bool>(new Uri("http://example.com/is_root"));

        private static string unencodedClaimSegment = 
            @"{""iss"":""joe"",
 ""exp"":1300819380,
 ""http://example.com/is_root"":true}";
    }

    public class When_decoding_malformed_strings
    {
        Because malformed_string_is_decoded = () =>
                Exception =
                Catch.Exception(
                    () => "I am not really base64 compatible".Base64UrlDecode());

        It should_throw_base64_Format_Exception =
            () => Exception.ShouldBeOfType<InvalidBase64StringFormatException>();

        protected static Exception Exception { get; set; }
    }
}