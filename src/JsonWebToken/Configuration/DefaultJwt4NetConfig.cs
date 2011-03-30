using System.Configuration;

namespace Jwt4Net.Configuration
{
    public class DefaultJwt4NetConfig
    {
        private static Jwt4NetXmlConfig _config =
            ConfigurationManager.GetSection("jwt4net") as Jwt4NetXmlConfig;

        public static Jwt4NetXmlConfig Instance
        {
            get
            {
                if (null == _config)
                    return new Jwt4NetXmlConfig();
                return _config;
            }
        }

        public static IIssuerConfig Issuer
        {
            get { return _config.Issuer; }
        }

        public static IConsumerConfig ReaderSettings
        {
            get { return _config.ReaderSettings; }
        }
    }
}