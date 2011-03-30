using Jwt4Net.Signing;

namespace Jwt4Net.Consumer.Validation
{
    public class SignatureMustBeValidRule : ITokenValidationRule
    {
        private readonly ICryptoProvider _cryptoBuilder;

        public SignatureMustBeValidRule(ICryptoProvider cryptoBuilder)
        {
            _cryptoBuilder = cryptoBuilder;
        }

        public bool Check(JsonWebToken token)
        {
            return  _cryptoBuilder.GetSignatureVerification(token.Header).Verify(token);
        }

        public string FailureMessage
        {
            get { return "The signature could not be validated for the token."; }
        }
    }
}