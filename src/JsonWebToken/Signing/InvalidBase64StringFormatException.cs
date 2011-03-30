using System;

namespace Jwt4Net.Signing
{
    public class InvalidBase64StringFormatException : FormatException
    {
        public InvalidBase64StringFormatException(string message)
            : base(message)
        {
        }

        public InvalidBase64StringFormatException(string message, Exception exception)
            : base(message, exception)
        {
        }
    }
}