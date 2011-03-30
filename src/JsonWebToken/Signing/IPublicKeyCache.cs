using System.Web;

namespace Jwt4Net.Signing
{
    public interface IPublicKeyCache
    {
        byte[] GetPublicKeyBytes(string uri, string keyId);
        void Cache(byte[] key, string keyId, string keyUri);
    }

    public class PublicKeyCache : IPublicKeyCache
    {
        const string prefix = "jwt4net::keycache::";

        public byte[] GetPublicKeyBytes(string uri, string keyId)
        {
            var uniqueId = prefix + keyId + "@" + uri;
            var cached = HttpRuntime.Cache.Get(uniqueId);
            if (null != cached)
                return (byte[]) cached;

            return null;
        }

        public void Cache(byte[] key, string keyId, string keyUri)
        {
            var uniqueId = prefix + keyId + "@" + keyUri;
            HttpRuntime.Cache.Insert(uniqueId, key);
        }
    }
}