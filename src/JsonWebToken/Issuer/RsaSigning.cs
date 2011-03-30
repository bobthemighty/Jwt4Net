using System.Security.Cryptography;
using System.Text;
using Jwt4Net.Signing;
using Security.Cryptography;

namespace Jwt4Net.Issuer
{
    public class RsaSigning : ITokenSigning
    {
        private readonly ICngKeyProvider _keyProvider;

        public RsaSigning(ICngKeyProvider keyProvider)
        {
            _keyProvider = keyProvider;
        }

        public byte[] GetSignature(string claimString)
        {
            using(var key = _keyProvider.GetKey())
            using(var dsa = new RSACng(key))
            {
                dsa.SignatureHashAlgorithm = CngAlgorithm.Sha256;
                return dsa.SignData(Encoding.UTF8.GetBytes(claimString));
            }
        }
    }
}