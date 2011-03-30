namespace Jwt4Net.Consumer.Validation
{
    public interface ITokenValidationRule : ITokenValidationFailure
    {
        bool Check(JsonWebToken token);
   }

    public interface ITokenValidationFailure
    {
        string FailureMessage { get; }        
    }
}