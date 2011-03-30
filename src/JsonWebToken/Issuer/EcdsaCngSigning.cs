using System.Text;
using System.Security.Cryptography;

namespace Jwt4Net.Signing
{
    public class EcdsaCngSigning : ITokenSigning
    {
        private readonly ICngKeyProvider _keyProvider;

        public EcdsaCngSigning(ICngKeyProvider keyProvider)
        {
            _keyProvider = keyProvider;
        }

        public byte[] GetSignature(string claimString)
        {
            CngKey key = _keyProvider.GetKey();

            using (_keyProvider.GetKey())
            using(var dsa = new ECDsaCng(key))
            {
                var bytes = Encoding.UTF8.GetBytes(claimString);
                return dsa.SignData(bytes);
            }
        }
    }
}
