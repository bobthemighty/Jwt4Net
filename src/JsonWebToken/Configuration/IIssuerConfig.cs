namespace Jwt4Net.Configuration
{
    public interface IIssuerConfig
    {
        string IssuerName { get; }
        IKeyConfig Key { get; }
    }
}
