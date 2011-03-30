using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Jwt4Net;
using Jwt4Net.Claims;
using Machine.Specifications;

namespace JsonWebTokenTests
{
    public class TestClaims
    {
        public static readonly ClaimDescriptor<int> Age
            // custom Claims are required to have URI names
            = new ClaimDescriptor<int>(new Uri("http://example.org/claims#age"));

        public static readonly ClaimDescriptor<List<Foo>> AllMyFoos
            = new ClaimDescriptor<List<Foo>>(new Uri("http://bunch-of-foos"));
    }

    public class When_fetching_a_string_claim
    {
        Establish claims_Are = () => claimset = new JsonClaimSet("{'iss': 'barry'}");

        Because a_claim_is_read = () => claim = claimset.Get(KnownClaims.Issuer);

        It should_contain_a_string = () => claim.Value.ShouldBeOfType<string>();
        It should_contain_the_right_value = () => claim.Value.ShouldEqual("barry");
        It should_contain_the_correct_name = () => claim.Name.ShouldEqual("iss");

        public static JsonClaimSet claimset { get; set; }
        public static IClaim<string> claim { get; set; }
    }

    public class When_fetching_an_integral_claim
    {
        Establish claims_Are = () => claimset = new JsonClaimSet("{'http://example.org/claims#age' : 21}");

        Because a_claim_is_read = () => claim = claimset.Get(TestClaims.Age);

        It should_contain_a_string = () => claim.Value.ShouldBeOfType<int>();
        It should_contain_the_right_value = () => claim.Value.ShouldEqual(21);
        It should_contain_the_correct_name = () => claim.Name.ShouldEqual("http://example.org/claims#age");

        public static JsonClaimSet claimset { get; set; }
        public static IClaim<int> claim { get; set; }
    }


    public class When_fetching_a_collection_claim
    {
        Establish the_claimset_is = () =>
            {
                var p = new Uri("urn:1234");
                claimset = new JsonClaimSet(
                    @"{ 'http://bunch-of-foos/': [
                         {'Name' : 'fred', 'Badgers' : 1}, 
                         {'Name': 'Arnold', 'Badgers': 43}
                        ]}");
            };

        Because claim_is_read = () => claim = claimset.Get(TestClaims.AllMyFoos);

        It should_contain_two_items = () => claim.Value.Count().ShouldEqual(2);
        It should_have_the_right_name_property = () => claim.Value.First().Name.ShouldEqual("fred");
        It should_have_the_right_badger_property = () => claim.Value.Last().Badgers.ShouldEqual(43);

        public static JsonClaimSet claimset { get; set; }
        public static IClaim<List<Foo>> claim { get; set; }
    }

    public class When_a_claim_is_not_present
    {
        Establish the_claimset_is = () => claimset = new JsonClaimSet(@"{'iss' : 'my-issuer'}");

        Because claim_is_read = () => claim = claimset.Get(KnownClaims.Expiry);

        It should_be_null = () => claim.ShouldBeOfType<NullClaim<UnixTimeStamp>>();

        private static JsonClaimSet claimset;

        private static IClaim<UnixTimeStamp> claim;
    }

    public class When_fetching_expiry
    {
        Establish the_claimset_is = () => claimset = new JsonClaimSet(@"{'iss' : 'my-issuer', 'exp': }");

        Because claim_is_read = () => claim = claimset.Get(KnownClaims.Expiry);

        It should_be_null = () => claim.ShouldBeOfType<NullClaim<UnixTimeStamp>>();

        private static JsonClaimSet claimset;

        private static IClaim<UnixTimeStamp> claim;
    }

    public class Foo
    {
        public string Name;
        public int Badgers;
    }
}
