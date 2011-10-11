using Microsoft.Practices.ServiceLocation;

namespace Jwt4Net
{
    public interface IContainerConfig
    {
        ServiceLocatorProvider Configure();

        IContainerConfig Replace<TService, TImplementation>(TImplementation instance = default(TImplementation))
            where TImplementation : class, TService
            where TService : class;
    }
}