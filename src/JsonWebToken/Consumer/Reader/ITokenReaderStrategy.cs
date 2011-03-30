namespace Jwt4Net.Consumer.Reader
{
    public interface ITokenReaderStrategy
    {
        JsonWebToken Read(string token);
    }
}