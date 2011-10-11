using System;
using System.Text;
using Penge;

namespace Cng2Pem.Tests
{
    internal class Utf8StringEncoding : IPayloadEncoding<string>
    {
        public string Decode(string payload)
        {
            var bytes = Convert.FromBase64String(payload);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
