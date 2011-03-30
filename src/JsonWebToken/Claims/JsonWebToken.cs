using System.Text;
using Jwt4Net.Signing;

namespace Jwt4Net
{
    public class JsonWebToken
    {

        public JsonWebTokenHeader Header
        {
            get;
            internal set;
        }

        public byte[] Signature
        {
            get;
            internal set;
        }

        public JsonClaimSet Claims { get; set; }

        public byte[] Payload { 
            get
            {
                return Encoding.UTF8.GetBytes(Header.OriginalString + "." + Claims.OriginalString);
            }
        }

        public string ToCompact()
        {
            return 
            string.Concat(
                Header.ToJson().Base64UrlEncode(),
                ".",
                Claims.ToJson().Base64UrlEncode(),
                ".",
                Signature.Base64UrlEncode());
        }
    }
}
