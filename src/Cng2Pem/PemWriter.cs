using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Penge
{
    public class PemWriter : IDisposable
    {
        private readonly Stream _stream;
        private static readonly byte[] Headerbytes = Encoding.ASCII.GetBytes("-----BEGIN PUBLIC KEY-----\n");
        private static readonly byte[] Footerbytes = Encoding.ASCII.GetBytes("-----END PUBLIC KEY-----\n");

        public PemWriter(Stream stream)
        {
            _stream = stream;
        }

        public void WritePublicKey(CngKey cngKey)
        {
            var writer = GetWriterFor(cngKey.Algorithm);
            
            _stream.Write(Headerbytes, 0, Headerbytes.Count());
            writer.Write(cngKey, _stream);
            _stream.Write(Footerbytes, 0, Footerbytes.Count());
        }

        
        private CngKeyWriter GetWriterFor(CngAlgorithm algorithm)
        {
            return new EccKeyWriter(algorithm);
        }

        public void Dispose()
        {
            _stream.Dispose();
        }
    }
}