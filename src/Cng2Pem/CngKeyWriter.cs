using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Penge
{
    internal abstract class CngKeyWriter
    {
        public abstract void Write(CngKey key, Stream stream);
    }

    internal class EccKeyWriter : CngKeyWriter
    {
        private readonly CngAlgorithm _algorithm;

        public EccKeyWriter(CngAlgorithm algorithm)
        {
            _algorithm = algorithm;
        }

        public override void Write(CngKey key, Stream stream)
        {
            int keySize;
            byte[] x;
            byte[] y;

            var keyBlob = key.Export(CngKeyBlobFormat.EccPublicBlob);
            
            unsafe
            {
                fixed(byte* pKeyBlob = keyBlob)
                {
                    var pBcryptBlob = (BCRYPT_ECCKEY_BLOB*) pKeyBlob;
                    var offset = Marshal.SizeOf(typeof (BCRYPT_ECCKEY_BLOB));

                    keySize = pBcryptBlob->KeySizeBytes;
                    x = new byte[keySize];
                    y = new byte[keySize];

                    Buffer.BlockCopy(keyBlob, offset, x, 0, keySize);
                    offset += keySize;
                    Buffer.BlockCopy(keyBlob, offset, y, 0, keySize);
                }
            }

            WriteInternal(keySize, x, y, stream);
        }

        private void WriteInternal(int keySize, byte[] x, byte[] y, Stream stream)
        {
            var bitString = new byte[] {Asn1Token.BitString}
                .Concat(GetLengthField(2 + keySize + keySize))
                .Concat(new byte[] {0x00, 0x04})
                .Concat(x)
                .Concat(y);

            var ecPublicKeyIdentifier = new byte[] {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
            var curveIdentifier = GetCurveIdentifier(_algorithm);

            var identifiers = new byte[]
                                    { 0x30, (byte) (ecPublicKeyIdentifier.Length + curveIdentifier.Length)}
                                    .Concat(ecPublicKeyIdentifier)
                                    .Concat(curveIdentifier);


        var sequence = new byte[] {0x30}.Concat(GetLengthField(bitString.Count() + identifiers.Count()));

            var eccPublicKeyString = Convert.ToBase64String(sequence.Concat(identifiers).Concat(bitString).ToArray());
            var lines = SplitToLines(eccPublicKeyString);

            var sw = new StreamWriter(stream);

            foreach(var line in SplitToLines(eccPublicKeyString))
                sw.Write(line+"\n");
            sw.Flush();
        }

        private static byte[] GetCurveIdentifier(CngAlgorithm algorithm)
        {

            if (algorithm == CngAlgorithm.ECDsaP256)
                return new byte[] {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
            if (algorithm == CngAlgorithm.ECDsaP384)
                return new byte[] {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
            if (algorithm == CngAlgorithm.ECDsaP521)
                return new byte[] {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};

            throw new UnsupportedCurveException("Unknown algorithm " + algorithm.Algorithm);
        }
        private IEnumerable<string> SplitToLines(string data)
        {
            const int maxLength = 64;

            var offset = 0;
            while(offset < data.Length)
            {
                var charsToRead = Math.Min(data.Length - offset, maxLength);
                yield return data.Substring(offset, charsToRead);
                offset += maxLength;
            }
        }

        private IEnumerable<byte> GetLengthField(int i)
        {
            var lengthBytes = BitConverter.GetBytes(i);
            if (i < 128)
            {
                yield return (byte) i;
                yield break;
            }

            yield return (byte)(128 | lengthBytes.Length );
            foreach (var b in lengthBytes)
                yield return b;
        }
    }

    internal class UnsupportedCurveException : Exception
    {
        public UnsupportedCurveException(string message)
            :base(message)
        {
            
        }
    }
}