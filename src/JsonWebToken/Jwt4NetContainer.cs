using System;
using Jwt4Net.Configuration;
using Jwt4Net.Configuration.Fluent;
using Microsoft.Practices.ServiceLocation;

namespace Jwt4Net
{
    public static class Jwt4NetContainer
    {
        static Jwt4NetContainer()
        {
            Configure();
        }
           
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

        public static void Configure()
        {
            Configure(new DefaultContainerConfig());
        }

        public static void Configure(FluentIssuerConfig withSymmetricKey = null, FluentConsumerConfig trustSymmetricIssuer = null)
        {
            Configure();
            var c = TinyIoC.TinyIoCContainer.Current;
            if (null != withSymmetricKey)
            {
                c.Register<IIssuerConfig>(withSymmetricKey);
                c.Register(withSymmetricKey.Key);
            }

            if(null != trustSymmetricIssuer)
            {
                c.Register<IConsumerConfig>(trustSymmetricIssuer);
            }
        }
    }
}
