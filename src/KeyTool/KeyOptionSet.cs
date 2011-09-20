using System;
using System.Collections.Generic;

namespace GenerateKey
{
    public class KeyOptionSet
    {
        public KeyType Algorithm { get; set; }

        public int KeySize { get; set; }

        public string KeyName { get; set; }

        public bool IsEphemeral { get; set; }

        public string Password { get; set; }

        public IEnumerable<string> GrantAccess { get; set; }

        public bool ExportPrivateKey { get; set; }

        public bool DoNotPersist { get; set; }

        public bool Valid { get; set; }
    }
}
