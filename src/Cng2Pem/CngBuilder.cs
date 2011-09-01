using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using Security.Cryptography;

namespace Penge
{
    public class CngBuilder
    {
        private readonly PemReader _theReader;

        public CngBuilder(PemReader theReader)
        {
            _theReader = theReader;
        }

        public CngKey Build()
        {
            if(_theReader.First().Header == "PUBLIC KEY")
            {
                using(var ms = new MemoryStream(_theReader.First().Body))
                using(var br = new BinaryReader(ms))
                {
                    // should have a sequence
                    br.Require(Asn1Token.Sequence);
                    // ignore the length
                    br.ReadLengthField();

                    // should have an inner sequence
                    br.Require(Asn1Token.Sequence);
                    // ignore the length
                    br.ReadLengthField();

                    //should have an OID
                    br.Require(Asn1Token.Oid);
                    // get its length
                    int oidLength = br.ReadByte();
                    var oid = Asn1Token.GetOid(br.ReadBytes(oidLength));
                    var builder = GetBuilderFor(oid);
                    return builder.Build(br);
                }
            }
            throw new NotImplementedException();
        }

        private CngKeyBuilderImpl GetBuilderFor(Asn1Token.KnownOid oid)
        {
            switch(oid)
            {
                case Asn1Token.KnownOid.EcPublicKey:
                    return new EllipticCurveCngKeyBuilder();
                case Asn1Token.KnownOid.RsaEncryptionPkcs1:
                    return new RsaCngKeyBuilder();
            }
            throw new UnsupportedCurveException("Unsupported key type with oid");
        }

    internal abstract class CngKeyBuilderImpl
    {
        public abstract CngKey Build(BinaryReader reader);
    }

        internal class EllipticCurveCngKeyBuilder : CngKeyBuilderImpl
    {
        public override CngKey Build(BinaryReader reader)
        {
            reader.Require(Asn1Token.Oid);
            var length = reader.ReadLengthField();
            var curve = Asn1Token.GetOid(reader.ReadBytes(length));
            if (!isSupportedCurve(curve))
            {
                throw new UnsupportedCurveException("Unsupported curve oid");
            }
            
            // We need to build a key blob structured as follows:
            //     BCRYPT_ECCKEY_BLOB   header
            //     byte[cbPublicExp]    publicExponent      - Exponent
            //     byte[cbModulus]      modulus             - Modulus
            //     -- Private only --
            //     byte[cbPrime1]       prime1              - P
            //     byte[cbPrime2]       prime2              - Q
            //

            // Where
            // typedef struct _BCRYPT_ECCKEY_BLOB {
            //  ULONG Magic; //BCRYPT_ECDSA_PUBLIC_P256_MAGIC =  0x31534345
            //  ULONG cbKey; // Key length in bytes
            //} B

            reader.Require(Asn1Token.BitString);
            var keyLength = reader.ReadLengthField() - 2;
            //ignore the zero byte
            reader.Require(0x00);

            // if this isn't an uncompressed curve, then panic
            reader.Require(0x04);

            var x = reader.ReadBytes(keyLength/2);
            var y = reader.ReadBytes(keyLength/2);

            return BuildEcKey(x, y, curve);
        }

        private static bool isSupportedCurve(Asn1Token.KnownOid curve)
        {
            return curve == Asn1Token.KnownOid.AnsiX9P256R1 || 
                   curve == Asn1Token.KnownOid.Secp384R1    ||
                   curve == Asn1Token.KnownOid.Secp521R1;
        }

        private unsafe CngKey BuildEcKey(byte[] x, byte[] y, Asn1Token.KnownOid curve)
        {
            int headerSize = Marshal.SizeOf(typeof (BCRYPT_ECCKEY_BLOB));
            int blobSize = headerSize + x.Length + y.Length;
            byte[] blobBytes = new byte[blobSize];
            
            fixed(byte* pBlobBytes = blobBytes)
            {
                BCRYPT_ECCKEY_BLOB* pBcryptEccBlob = (BCRYPT_ECCKEY_BLOB*) pBlobBytes;
                pBcryptEccBlob->KeyBlobMagicNumber = GetMagicNumber(curve);
                pBcryptEccBlob->KeySizeBytes = x.Length;

                Buffer.BlockCopy(x, 0, blobBytes, headerSize, x.Length);
                Buffer.BlockCopy(y, 0, blobBytes, headerSize+x.Length, y.Length);
            }

            new KeyContainerPermission(KeyContainerPermissionFlags.Import).Assert();
            var key = CngKey.Import(blobBytes, CngKeyBlobFormat.EccPublicBlob);
            CodeAccessPermission.RevertAssert();
            return key;
        }

            private static int GetMagicNumber(Asn1Token.KnownOid curve)
            {
                switch(curve)
                {
                    case Asn1Token.KnownOid.AnsiX9P256R1:
                        return 0x31534345;
                    case Asn1Token.KnownOid.Secp384R1:
                        return 0x33534345;
                    case Asn1Token.KnownOid.Secp521R1:
                        return 0x35534345;
                }
                throw new UnsupportedCurveException("Unsupported elliptic curve domain");
            }
    }
    }

    internal class RsaCngKeyBuilder : CngBuilder.CngKeyBuilderImpl
    {
        public override CngKey Build(BinaryReader reader)
        {
            // skip NULL 
            reader.Require(Asn1Token.Null);
            reader.ReadLengthField();

            reader.Require(Asn1Token.BitString);
            // length
            reader.ReadLengthField();
            // unused buts
            reader.Skip();

            reader.Require(Asn1Token.Sequence);
            reader.ReadLengthField();

            // Modulus
            reader.Require(Asn1Token.Integer);
            var modLength = reader.ReadLengthField();
            // if the first byte is zero, skip it.
            if (reader.Peek() == 0x00)
            {
                modLength--;
                reader.Skip();
            }
            var modulus = reader.ReadBytes(modLength);

            // Exponent
            reader.Require(Asn1Token.Integer);
            var expLength = reader.ReadLengthField();
            var exponent = reader.ReadBytes(expLength);

            var parameters = new RSAParameters()
            {
                Exponent = exponent,
                Modulus = modulus
            };
            var cng = new RSACng();
            cng.ImportParameters(parameters);

            return cng.Key;
        }
    }
}