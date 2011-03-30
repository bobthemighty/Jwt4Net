using System;
using Castle.MicroKernel;
using Microsoft.Practices.ServiceLocation;

namespace Jwt4Net.WindsorConfiguration
{
    public class WindsorConfiguration : IContainerConfig
    {
        private readonly IKernel _kernel;

        public WindsorConfiguration(IKernel kernel)
        {
            _kernel = kernel;
        }

        public ServiceLocatorProvider Configure()
        {


            return () => _kernel;
        }
    }

  
}
