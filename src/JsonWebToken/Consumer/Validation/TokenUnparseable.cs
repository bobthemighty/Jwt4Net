namespace Jwt4Net.Consumer.Validation
{
    public class TokenUnparseable : ITokenValidationFailure
    {
        public TokenUnparseable()
        {
            FailureMessage = "The token is invalid and can not be consumed.";
        }

        public string FailureMessage
        {
            get; set;
        }
    }
}