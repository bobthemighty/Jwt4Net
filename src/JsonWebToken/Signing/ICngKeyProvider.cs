using System.Configuration;
using System.Security.Cryptography;
using Jwt4Net.Configuration;

namespace Jwt4Net.Signing
{
    public interface ICngKeyProvider
    {
        CngKey GetKey();
    }

    public class CngKeyProvider : ICngKeyProvider
    {
        private readonly IKeyConfig _keyConfig;

        public CngKeyProvider(IKeyConfig keyConfig)
        {
            _keyConfig = keyConfig;
        }

        public CngKey GetKey()
        {
            CngKey key;
            var options = _keyConfig.IsUserKey ? CngKeyOpenOptions.UserKey : CngKeyOpenOptions.MachineKey;
            if (!CngKey.Exists(_keyConfig.LocalName, CngProvider.MicrosoftSoftwareKeyStorageProvider, options))
                throw new ConfigurationErrorsException("No " + options + " could be found for the id " + _keyConfig.LocalName);

            key = CngKey.Open(_keyConfig.LocalName, CngProvider.MicrosoftSoftwareKeyStorageProvider, options);
            return key;
        }
    }
}