using System.Collections.Generic;
using Jwt4Net.Consumer.Validation;
using Jwt4Net.Signing;
using LitJson;

namespace Jwt4Net.Consumer
{
    public class TokenConsumer : ITokenConsumer
    {
        private readonly ITokenReader _reader;
        private readonly IEnumerable<ITokenValidationRule> _rules;

        public TokenConsumer(ITokenReader reader, IEnumerable<ITokenValidationRule> rules)
        {
            _reader = reader;
            _rules = rules;
        }

        public bool TryConsume(string tokenString, out JsonWebToken token)
        {
            JsonWebToken candidateToken;
            try
            {
                candidateToken = _reader.Read(tokenString);
            }
            catch (InvalidTokenFormatException e)
            {
                token = null;
                FailureReason = new TokenUnparseable { FailureMessage = e.Message };
                return false;
            }
            catch(InvalidBase64StringFormatException e)
            {
                token = null;
                FailureReason = new TokenUnparseable {FailureMessage = e.Message};
                return false;
            }
            catch(JsonException e)
            {
                token = null;
                FailureReason = new TokenUnparseable {FailureMessage = e.Message};
                return false;
            }

            foreach(var rule in _rules)
            {
                if(false == rule.Check(candidateToken))
                {
                    FailureReason = rule;
                    token = null;
                    return false;
                }
            }
            token = candidateToken;
            return true;
        }

        public ITokenValidationFailure FailureReason
        {
            get; private set;
        }
    }
}