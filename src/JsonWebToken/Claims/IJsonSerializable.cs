using LitJson;

namespace Jwt4Net
{
    public interface IJsonSerializable
    {
        void Serialize(JsonWriter w);
    }
}