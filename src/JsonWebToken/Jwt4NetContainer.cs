using System;
using Jwt4Net.Configuration;
using Jwt4Net.Configuration.Fluent;
using Jwt4Net.Consumer.Validation;
using Microsoft.Practices.ServiceLocation;
using TinyIoC;

namespace Jwt4Net
{
    public static class Jwt4NetContainer
    {
        public static ITokenIssuer CreateIssuer()
        {
            return ServiceLocator.Current.GetInstance<ITokenIssuer>();
        }

        public static ITokenConsumer CreateConsumer()
        {
            return ServiceLocator.Current.GetInstance<ITokenConsumer>();
        }

        public static void Configure(IContainerConfig config)
        {
            ServiceLocator.SetLocatorProvider(config.Configure());
        }

        public static void Configure(FluentConsumerConfig consumerConfig = null, FluentIssuerConfig withSymmetricKey = null)
        {
            Configure(withSymmetricKey, consumerConfig);
        }

        public static void Configure(FluentIssuerConfig withSymmetricKey = null, FluentConsumerConfig consumerConfig = null)
        {
            var c = new TinyIoCContainer();
            var cfg = new DefaultContainerConfig(c);
           
            if (null != withSymmetricKey)
            {
                c.Register<IIssuerConfig>(withSymmetricKey);
                c.Register(withSymmetricKey.Key);
            }

            if(null != consumerConfig)
            {
                c.Register<IConsumerConfig>(consumerConfig);
                foreach(var rule in consumerConfig.IgnoredRules)
                {
                    c.RemoveRegistration(new TinyIoCContainer.TypeRegistration(typeof(ITokenValidationRule), rule.FullName));
                }
            }

            ServiceLocator.SetLocatorProvider(() =>cfg);
        }
    }
}
