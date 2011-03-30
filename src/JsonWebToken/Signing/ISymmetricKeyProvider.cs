using Jwt4Net.Configuration;

namespace Jwt4Net.Signing
{
    public interface ISymmetricKeyProvider
    {
        byte[] GetKey(SigningAlgorithm algorithm);
    }

    public class ConfigFileSymmetricKeyProvider : ISymmetricKeyProvider
    {
        private readonly IKeyConfig _config;

        public ConfigFileSymmetricKeyProvider(IKeyConfig config)
        {
            _config = config;
        }

        public byte[] GetKey(SigningAlgorithm algorithm)
        {
            return _config.KeyValue;
        }
    }
}