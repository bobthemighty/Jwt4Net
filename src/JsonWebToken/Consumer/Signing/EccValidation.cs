using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Jwt4Net.Signing;

namespace Jwt4Net.Consumer.Signing
{
    public interface IEccPublicKeyProvider
    {
        ECDsaCng LoadRemoteKey(JsonWebTokenHeader header);
    }

    public class EccPublicKeyProvider : IEccPublicKeyProvider
    {
        private readonly IPublicKeyCache _cache;

        public EccPublicKeyProvider(IPublicKeyCache cache)
        {
            _cache = cache;
        }

        public ECDsaCng LoadRemoteKey(JsonWebTokenHeader header)
        {
            var dsa = new ECDsaCng();
            var cached = _cache.GetPublicKeyBytes(header.KeyUri.ToString(), header.KeyId);
            if (null != cached)
            {
                dsa.FromXmlString(Encoding.UTF8.GetString(cached), ECKeyXmlFormat.Rfc4050);
                return dsa;
            }

            string data;
            using (var wc = new WebClient())
            {
                try
                {
                    data = wc.DownloadString(header.KeyUri);
                }
                catch (WebException e)
                {
                    throw new RemoteKeyInaccessibleException("Unable to download the public key from URI " + header.KeyUri, e);
                }
            }

            switch (header.KeyFormat)
            {
                case KeyFormat.Rfc4050:

                    dsa.FromXmlString(data, ECKeyXmlFormat.Rfc4050);
                    _cache.Cache(Encoding.UTF8.GetBytes(data), header.KeyId, header.KeyUri.ToString());
                    return dsa;
            }
            throw new NotSupportedException("Can not open an ECC key with the keyformat " + header.KeyFormat);
        }
    }

    public class EccValidation : ITokenVerifier
    {
        private readonly IEccPublicKeyProvider _keyProvider;

        public EccValidation(IEccPublicKeyProvider keyProvider)
        {
            _keyProvider = keyProvider;
            ;
        }

        public bool Verify(JsonWebToken token)
        {
            var dsa = _keyProvider.LoadRemoteKey(token.Header);
            var data = token.Payload;
            var signature = token.Signature;
            return dsa.VerifyData(data, signature);
        }
    }

    internal class RemoteKeyInaccessibleException : Exception
    {
        public RemoteKeyInaccessibleException(string message, Exception innerException)
           : base(message, innerException)
        {
        }
    }
}