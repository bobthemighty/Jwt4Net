namespace Jwt4Net
{
    public interface IClaim<T> : IJsonSerializable
    {
        T Value { get; }
        string Name { get; }
    }
}