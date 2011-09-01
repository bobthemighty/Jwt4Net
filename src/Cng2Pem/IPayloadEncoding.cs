namespace Penge
{
    public interface IPayloadEncoding<T>
    {
        T Decode(string payload);
    }
}