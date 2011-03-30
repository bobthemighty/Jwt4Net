using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jwt4Net
{
    public class InvalidTokenDataException : ArgumentOutOfRangeException
    {
       public InvalidTokenDataException(string message)
        : base (message)
        {
        }
    }
}
