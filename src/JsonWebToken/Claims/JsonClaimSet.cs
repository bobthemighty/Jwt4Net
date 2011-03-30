using System.Linq;
using System.Text;
using Jwt4Net.Claims;
using Jwt4Net.Signing;
using LitJson;

namespace Jwt4Net
{
    public class JsonClaimSet
    {
        private readonly JsonData _json;

        public JsonClaimSet(string encodedJson)
        {
            string decodedJson = encodedJson.FirstOrDefault() == '{' ? 
                    encodedJson
                  : encodedJson.Base64UrlDecode(Encoding.UTF8);
            
            OriginalString = encodedJson;
            _json = JsonMapper.ToObject(decodedJson);
        }

        public IClaim<T> Get<T>(IClaimDescriptor<T> Descriptor)
        {
            return Descriptor.Read(_json);
        }

        internal string ToJson()
        {
            return _json.ToJson();
        }

        public string OriginalString
        {
            get; private set;
        }
    }
}
