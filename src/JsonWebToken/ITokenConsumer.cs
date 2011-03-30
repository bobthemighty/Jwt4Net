using Jwt4Net.Consumer.Validation;

namespace Jwt4Net
{
    public interface ITokenConsumer
    {
        bool TryConsume(string tokenString, out JsonWebToken token);
        ITokenValidationFailure FailureReason { get; }
    }
}