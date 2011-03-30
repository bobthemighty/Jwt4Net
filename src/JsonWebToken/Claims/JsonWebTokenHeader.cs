using System;
using System.Text;
using Jwt4Net.Signing;
using LitJson;

namespace Jwt4Net
{
    public class JsonWebTokenHeader
    {
        private readonly string _originalData;
        private SigningAlgorithm _algorithm;

        internal JsonWebTokenHeader()
        {
        }

        public JsonWebTokenHeader(string originalData)
        {
            _originalData = originalData;
            var reader = new JsonReader(originalData.Base64UrlDecode(Encoding.UTF8));
            while (reader.Read())
            {
                if (reader.Token == JsonToken.PropertyName)
                {
                    switch (reader.Value.ToString())
                    {
                        case "alg":
                            reader.Read();
                            SetAlgorithm((string)reader.Value);
                            break;
                        case "kid":
                            reader.Read();
                            KeyId = (string)reader.Value;
                            break;
                        case "xdu":
                            reader.Read();
                            KeyFormat = KeyFormat.Rfc4050;
                            KeyUri = new Uri((string)reader.Value);
                            break;
                        case "jku":
                            reader.Read();
                            KeyFormat = KeyFormat.Json;
                            KeyUri = new Uri((string)reader.Value);
                            break;
                        case "xku":
                            reader.Read();
                            KeyFormat = KeyFormat.X509;
                            KeyUri = new Uri((string)reader.Value);
                            break;
                    }
                }

            }
        }

        public Uri KeyUri { get; internal set; }

        public string KeyId { get; internal set; }

        public KeyFormat KeyFormat { get; internal set; }

        private void SetAlgorithm(string value)
        {
            switch (value)
            {
                case "HS256":
                case "HS384":
                case "HS512":
                case "RS256":
                case "RS384":
                case "RS512":
                case "ES256":
                case "ES384":
                case "ES512":
                    Algorithm = ((SigningAlgorithm)Enum.Parse(typeof(SigningAlgorithm), value));
                    break;
                default:
                    throw new InvalidTokenDataException("Unrecognised value for signing algorithm");
            }
        }

        public SigningAlgorithm Algorithm
        {
            get { return _algorithm; }
            internal set
            {
                _algorithm = value;
            }
        }

        public string OriginalString
        {
            get {
                return _originalData;
            }
        }

        public string ToJson()
        {
            var jsWriter = new JsonWriter();
            jsWriter.WriteObjectStart();
            jsWriter.WritePropertyName("alg");
            jsWriter.Write(Algorithm.ToString());

            if (null != KeyUri)
            {
                switch (KeyFormat)
                {
                    case KeyFormat.Json:
                        jsWriter.WritePropertyName("jku");
                        break;
                    case KeyFormat.X509:
                        jsWriter.WritePropertyName("xku");
                        break;
                    case KeyFormat.Rfc4050:
                        jsWriter.WritePropertyName("xdu");
                        break;
                }
                jsWriter.Write(KeyUri.ToString());
            }

            if (false == string.IsNullOrEmpty(KeyId))
            {
                jsWriter.WritePropertyName("kid");
                jsWriter.Write(KeyId);
            }
            jsWriter.WriteObjectEnd();
            return jsWriter.ToString();
        }
    }

    public enum KeyFormat
    {
        Rfc4050,
        Json,
        X509
    }
}
