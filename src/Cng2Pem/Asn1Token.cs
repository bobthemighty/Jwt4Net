using System;
using System.Collections.Generic;

namespace Penge
{
    internal static class Asn1Token
    {
        public const byte Oid = 0x06;
        public const byte Sequence = 0x30;

        public static KnownOid GetOid(byte[] bytes)
        {
            var key = bytes.ToKey();
            if (_oidMap.ContainsKey(key))
                return _oidMap[key];
            return KnownOid.None;
        }

        public enum KnownOid
        {
            None,
            RsaEncryptionPkcs1,
            EcPublicKey,
            AnsiX9P256R1,
            Secp384R1,
            Secp521R1
        }

        private static readonly Dictionary<string, KnownOid> _oidMap = new Dictionary<string, KnownOid>
                                                                           {
                                                                               {new byte[]{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }.ToKey(), KnownOid.RsaEncryptionPkcs1},
                                                                               {new byte[] {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}.ToKey(), KnownOid.EcPublicKey},

                                                                               // EC curves
                                                                               {new byte[]{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}.ToKey(), KnownOid.AnsiX9P256R1},
                                                                               {new byte[]{0x2B, 0x81, 0x04, 0x00, 0x22}.ToKey(), KnownOid.Secp384R1},
                                                                               {new byte[]{0x2B, 0x81, 0x04, 0x00, 0x23}.ToKey(), KnownOid.Secp521R1},
                                                                           };

        public static byte Integer = 0x02;

        public const byte BitString = 0x03;

        public const byte Null = 0x05;

        public static string ToKey(this byte[] oid)
        {
            return Convert.ToBase64String(oid);
        }
    }
}