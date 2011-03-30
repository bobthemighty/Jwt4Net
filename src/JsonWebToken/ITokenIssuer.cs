using Jwt4Net.Claims;

namespace Jwt4Net
{
    public interface ITokenIssuer
    {
        void Set<T>(IClaimDescriptor<T> key, T value);
        string Sign();

        ITokenIssuer Create();
    }
}