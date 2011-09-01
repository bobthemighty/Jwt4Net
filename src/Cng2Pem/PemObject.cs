namespace Penge
{
    public class PemObject
    {
        public PemObject(string header, byte[] body)
        {
            Header = header;
            Body = body;
        }

        public string Header { get; private set; }
        public byte[] Body { get; private set; }
    }
}