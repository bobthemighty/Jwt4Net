using System.Configuration;
using System.Text;
using Jwt4Net.Configuration;
using Jwt4Net.Signing;

namespace Jwt4Net
{
    public interface ITokenReader
    {
        JsonWebToken Read(string token);
    }

    public class TokenReader : ITokenReader
    {
        private readonly IConsumerConfig _settings;

        public TokenReader(IConsumerConfig settings)
        {
            _settings = settings;
        }

        public JsonWebToken Read(string token)
        {
            if(token.StartsWith("{"))
            {
                if (_settings.AllowUnsignedTokens)
                    return ReadUnsigned(new[] {token});
                throw new InvalidTokenFormatException("Json web tokens must be of the form header.body.signature");
            }
            var parts = token.Split('.');
            if (parts.Length < 3)
            {
                if (_settings.AllowUnsignedTokens)
                    return ReadUnsigned(parts);
                throw new InvalidTokenFormatException("Json web tokens must be of the form header.body.signature");
            }

            return new JsonWebToken
            {
                Signature = parts[2].Base64UrlDecode(),
                Header = new JsonWebTokenHeader(parts[0]),
                Claims = new JsonClaimSet(parts[1]),
                OriginalString = token
            };
        }

        private static JsonWebToken ReadUnsigned(string[] tokenParts)
        {
            if (tokenParts.Length == 2)
                return new JsonWebToken
                           {
                               Header = new JsonWebTokenHeader(ReadPart(tokenParts[0])),
                               Claims = new JsonClaimSet(ReadPart(tokenParts[1])),
                               OriginalString = string.Join(".", tokenParts)
                           };

            return new JsonWebToken {Claims = new JsonClaimSet(ReadPart(tokenParts[0])), OriginalString = tokenParts[0]};
        }

        private static string ReadPart(string part)
        {
            if (string.IsNullOrEmpty(part))
                return string.Empty;
            if (part[0] == '{')
                return part;
            return part.Base64UrlDecode(Encoding.UTF8);
        }


    }
}
