using System;
using System.Collections.Generic;
using System.Linq;
using Jwt4Net.Consumer.Validation;
using Microsoft.Practices.ServiceLocation;

namespace Jwt4Net.Configuration
{
    public class DefaultContainerConfig : IContainerConfig, IServiceLocator
    {
        static DefaultContainerConfig()
        {
            var c = TinyIoC.TinyIoCContainer.Current;
            
            c.AutoRegister(typeof(ITokenIssuer).Assembly);
            c.Register(DefaultJwt4NetConfig.Instance);
            c.Register(DefaultJwt4NetConfig.Instance.ReaderSettings);
            c.Register(DefaultJwt4NetConfig.Instance.Issuer);
            c.Register(DefaultJwt4NetConfig.Instance.Issuer.Key);

            c.RegisterMultiple<ITokenValidationRule>(new [] {typeof (IssuerMustBeTrustedRule), typeof (SignatureMustBeValidRule), typeof(ExpiryDateMustBeInThePastRule)});
        }

        public ServiceLocatorProvider Configure()
        {
            return () => new DefaultContainerConfig();
        }

        public object GetService(Type serviceType)
        {
            return TinyIoC.TinyIoCContainer.Current.Resolve(serviceType);
        }

        public object GetInstance(Type serviceType)
        {
            return TinyIoC.TinyIoCContainer.Current.Resolve(serviceType);
        }

        public object GetInstance(Type serviceType, string key)
        {
            return TinyIoC.TinyIoCContainer.Current.Resolve(serviceType, key);
        }

        public IEnumerable<object> GetAllInstances(Type serviceType)
        {
            return TinyIoC.TinyIoCContainer.Current.ResolveAll(serviceType);
        }

        public TService GetInstance<TService>()
        {
            return (TService)TinyIoC.TinyIoCContainer.Current.Resolve(typeof(TService));
        }

        public TService GetInstance<TService>(string key)
        {
            return (TService)TinyIoC.TinyIoCContainer.Current.Resolve(typeof(TService), key);
        }

        public IEnumerable<TService> GetAllInstances<TService>()
        {
            return TinyIoC.TinyIoCContainer.Current.ResolveAll(typeof(TService)).Select(s => (TService)s);
        }
    }
}