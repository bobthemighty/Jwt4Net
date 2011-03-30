using System;
using System.Text;

namespace Jwt4Net.Signing
{
    public static class Base64Encoder
    {
        public static string Base64UrlEncode(this byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Standard base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        public static string Base64UrlEncode(this string arg)
        {
            return Encoding.UTF8.GetBytes(arg).Base64UrlEncode();
        }

        public static string Base64UrlDecode(this string arg, Encoding encoding)
        {
            return encoding.GetString(
                arg.Base64UrlDecode());
        }

        public static byte[] Base64UrlDecode(this string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new InvalidBase64StringFormatException("Invalid length for base64url encoded string");
            }
            try
            {
                return Convert.FromBase64String(s); // Standard base64 decoder
            }
            catch (FormatException e)
            {
                throw new InvalidBase64StringFormatException("Invalid base64url encoded string", e);
            }
                    }
    }
}
