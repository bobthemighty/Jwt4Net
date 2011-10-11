using System;

namespace Jwt4Net.Consumer
{
    public class InvalidTokenFormatException : FormatException
    {
        public InvalidTokenFormatException(string message)
            :base (message)
        {
        }
    }
}
