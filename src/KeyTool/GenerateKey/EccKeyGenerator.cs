using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace GenerateKey
{
    public class EccKeyGenerator
    {
        private KeyOptionSet options;

        public EccKeyGenerator(KeyOptionSet options)
        {
            this.options = options;
            var algorithm = GetAlgorithm();
            var parameters = GetParameters();
            Result = CngKey.Create(algorithm, 
                options.IsEphemeral? null : options.KeyName, 
                parameters);

            
            
            
        }

        private CngKeyCreationParameters GetParameters()
        {
            return new CngKeyCreationParameters
                       {
                           ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                           KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey | CngKeyCreationOptions.MachineKey
            };
        }

        private CngAlgorithm GetAlgorithm()
        {
            if (0 == options.KeySize) options.KeySize = 256;
            switch (options.KeySize)
            {
                case 256:
                    return CngAlgorithm.ECDsaP256;
                case 384:
                    return CngAlgorithm.ECDsaP384;
                case 521:
                    return CngAlgorithm.ECDsaP521;
            }

            throw new NotSupportedException();
        }

        public CngKey Result
        { get; private set; }
    }
}
