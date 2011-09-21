using System;
using System.IO;

namespace Penge
{
    internal static class BinaryReaderExtensions
    {
        public static void Require(this BinaryReader reader, params byte[] sequence)
        {
            foreach(var b in sequence)
            {
                var actual = reader.ReadByte();
                if(b != actual)
                    throw new FormatException("Failed to read pem file, expected "+b.ToString("x")+" but was "+actual.ToString("x"));
            }
        }

        public static byte Peek(this BinaryReader reader)
        {
            var b =reader.ReadByte();
            reader.BaseStream.Seek(-1, SeekOrigin.Current);
            return b;
        }

        public static void Skip(this BinaryReader reader, int count)
        {
            reader.ReadBytes(count);
        }

        public static void Skip(this BinaryReader reader)
        {
            reader.Skip(1);
        }

        public static int ReadLengthField(this BinaryReader reader)
        {
            var b = reader.ReadByte();
            if((b & 128) == 128)
            {
                b ^= 128;
                switch(b)
                {
                    case 1:
                        return reader.ReadByte();
                    case 2:
                        return reader.ReadInt16();
                    case 4:
                        return reader.ReadInt32();
                }
            }
            else
            {
                return b;
            }
            throw new FormatException("unable to handle length fields with length "+b);
        }
    }
}