namespace Jwt4Net.Configuration.Fluent
{
    public class FluentIssuerConfig : IIssuerConfig
    {
        private readonly string _name;
        private FluentKeyConfig _key;

        public FluentIssuerConfig(string name)
        {
            _name = name;
            _key = new FluentKeyConfig();
        }

        public string IssuerName
        {
            get { return _name; }
        }

        public IKeyConfig Key
        {
            get { return _key; }
        }


        internal class FluentKeyConfig : IKeyConfig
        {
            public SigningAlgorithm Algorithm { get;  set; }
            public KeyFormat KeyFormat { get;  set; }
            public string LocalName { get; set; }
            public string RemoteId { get; set; }
            public string RemoteUri { get; set; }
            public bool IsUserKey { get; set; }
            public string KeyValue { get; set; }
        }

        public FluentIssuerConfig WithSymmetricKey(string keyValue, SigningAlgorithm algorithm)
        {
            _key.Algorithm = algorithm;
            _key.KeyValue = keyValue;
            return this;
        }
    }
}