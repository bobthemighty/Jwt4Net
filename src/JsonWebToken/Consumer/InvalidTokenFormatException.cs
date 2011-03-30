using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jwt4Net
{
    public class InvalidTokenFormatException : FormatException
    {
        private string p;

        public InvalidTokenFormatException(string message)
            :base (message)
        {
        }
    }
}
