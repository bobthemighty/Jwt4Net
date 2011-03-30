using System.Collections.Generic;

namespace Jwt4Net.Configuration
{
    public interface IConsumerConfig
    {
        bool AllowUnsignedTokens { get; }
        IEnumerable<IIssuer> TrustedIssuers { get; }
    }
}
