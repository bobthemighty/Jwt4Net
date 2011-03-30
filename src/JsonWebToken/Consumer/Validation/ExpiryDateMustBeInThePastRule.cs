using System;
using Jwt4Net.Claims;

namespace Jwt4Net.Consumer.Validation
{
    public class ExpiryDateMustBeInThePastRule : ITokenValidationRule
    {
        public bool Check(JsonWebToken token)
        {
            var expiry = token.Claims.Get(KnownClaims.Expiry);
            if(expiry is NullClaim<UnixTimeStamp>)
            {
                FailureMessage = "The token did not contain a parseable expiry date.";
                return false;
            }

            if(expiry.Value.ToDateTime() < DateTime.UtcNow)
            {
                FailureMessage = "The expiry date '" + expiry.Value.ToDateTime() + "' (unix:" + expiry.Value.Value +") is in the past.";
                return false;
            }

            return true;
        }

        public string FailureMessage
        {
            get; private set;
        }
    }
}
