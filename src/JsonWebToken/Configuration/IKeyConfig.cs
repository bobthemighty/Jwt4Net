namespace Jwt4Net.Configuration
{
    public interface IKeyConfig
    {
        SigningAlgorithm Algorithm { get; }
        KeyFormat KeyFormat { get;}
        string LocalName { get;  }
        string RemoteId { get; }
        string RemoteUri { get; }
        bool IsUserKey { get; }
        byte[] KeyValue { get; }
    }
}
