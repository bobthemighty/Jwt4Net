using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Jwt4Net.Consumer.Validation;
using Microsoft.Practices.ServiceLocation;
using TinyIoC;

namespace Jwt4Net.Configuration
{
    public class DefaultContainerConfig : IContainerConfig, IServiceLocator
    {
        private TinyIoCContainer _container;
        private bool _configured = false;

        public DefaultContainerConfig(TinyIoCContainer tinyIoCContainer)
        {
            _container = tinyIoCContainer;
            Configure(tinyIoCContainer);
        }

        public DefaultContainerConfig()
        {
            _container = new TinyIoCContainer();
        }

        public ServiceLocatorProvider Configure()
        {
            if (_configured) return () => this;
            _container = new TinyIoCContainer();
            return Configure(_container);
        }

        public IContainerConfig Replace<TService, TImplementation>(TImplementation instance) where TImplementation : class, TService where TService : class
        {
            if(default(TImplementation) != instance)
                _container.Register<TService, TImplementation>(instance);
            else
                _container.Register<TService, TImplementation>();
            return this;
        }

        private ServiceLocatorProvider Configure(TinyIoCContainer container)
        {
            container.AutoRegister(new[] { GetType().Assembly });
            container.Register(DefaultJwt4NetConfig.Instance);
            container.Register(DefaultJwt4NetConfig.Instance.ReaderSettings);
            container.Register(DefaultJwt4NetConfig.Instance.Issuer);
            container.Register(DefaultJwt4NetConfig.Instance.Issuer.Key);

            container.RegisterMultiple<ITokenValidationRule>(new[] { typeof(IssuerMustBeTrustedRule), typeof(SignatureMustBeValidRule), typeof(ExpiryDateMustBeInThePastRule) });
            _configured = true;
            return () => this;
        }

        public object GetService(Type serviceType)
        {
            return _container.Resolve(serviceType);
        }

        public object GetInstance(Type serviceType)
        {
            return _container.Resolve(serviceType);
        }

        public object GetInstance(Type serviceType, string key)
        {
            return _container.Resolve(serviceType, key);
        }

        public IEnumerable<object> GetAllInstances(Type serviceType)
        {
            return _container.ResolveAll(serviceType);
        }

        public TService GetInstance<TService>()
        {
            return (TService)_container.Resolve(typeof(TService));
        }

        public TService GetInstance<TService>(string key)
        {
            return (TService)_container.Resolve(typeof(TService), key);
        }

        public IEnumerable<TService> GetAllInstances<TService>()
        {
            return _container.ResolveAll(typeof(TService)).Select(s => (TService)s);
        }
    }
}