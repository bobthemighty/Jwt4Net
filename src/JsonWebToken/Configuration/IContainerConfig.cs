using Microsoft.Practices.ServiceLocation;

namespace Jwt4Net
{
    public interface IContainerConfig
    {
        ServiceLocatorProvider Configure();
    }
}