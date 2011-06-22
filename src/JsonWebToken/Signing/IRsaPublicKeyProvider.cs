using System;
using Security.Cryptography;

namespace Jwt4Net.Signing
{
    public interface IRsaPublicKeyProvider
    {
        RSACng LoadRemoteKey(JsonWebTokenHeader header);
    }

    public class RsaPublicKeyProvider : IRsaPublicKeyProvider
    {
        public RSACng LoadRemoteKey(JsonWebTokenHeader header)
        {
            throw new NotImplementedException();
        }
    }
}