using Security.Cryptography;

namespace Jwt4Net.Signing
{
    public interface IRsaPublicKeyProvider
    {
        RSACng LoadRemoteKey(JsonWebTokenHeader header);
    }
}