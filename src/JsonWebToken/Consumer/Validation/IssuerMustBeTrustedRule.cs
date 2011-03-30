using System.Linq;
using System.Text.RegularExpressions;
using Jwt4Net.Configuration;
using Jwt4Net.Signing;

namespace Jwt4Net.Consumer.Validation
{
    public class IssuerMustBeTrustedRule : ITokenValidationRule
    {
        private string issuer;
        private IConsumerConfig _config;

        public IssuerMustBeTrustedRule(IConsumerConfig config)
        {
            _config = config;
        }

        public bool Check(JsonWebToken token)
        {
            issuer = token.Claims.Get(KnownClaims.Issuer).Value;
            var trusted = _config.TrustedIssuers.FirstOrDefault(i => i.Name == issuer);
            if(null == trusted)
            {
                FailureMessage = issuer + " is not a trusted issuer";
                return false;
            }
            
            if(null == token.Header)
            {
                if (_config.AllowUnsignedTokens)
                    return true;
                FailureMessage = "No header was included in the token, unable to validate keys.";
                return false;
            }

            if(token.Header.Algorithm.IsHmac())
            {
                return true;
            }

            var pattern = new Regex(trusted.KeyUriPattern);
            if(false == pattern.IsMatch(token.Header.KeyUri.ToString()))
            {
                FailureMessage = "The Uri " + token.Header.KeyUri + " is not trusted for the issuer " + issuer;
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