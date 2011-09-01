using System.Runtime.InteropServices;

namespace Penge
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct BCRYPT_ECCKEY_BLOB
    {
        internal int KeyBlobMagicNumber;
        internal int KeySizeBytes;
    }
}