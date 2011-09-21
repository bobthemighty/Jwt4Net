using System;

namespace Penge
{
    internal class InvalidPemDocumentException : Exception
    {
        public InvalidPemDocumentException(string message)
            :base(message)
        {
        }
    }
}