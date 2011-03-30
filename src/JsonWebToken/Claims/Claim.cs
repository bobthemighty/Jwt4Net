using LitJson;

namespace Jwt4Net
{
    public class Claim<T> : IClaim<T>
    {
        public Claim(string name, T value)
        {
            Value = value;
            Name = name;
        }

        public T Value
        {
            get;
            private set;
        }

        public string Name
        {
            get;
            private set;
        }

        public void Serialize(JsonWriter w)
        {
            w.WritePropertyName(Name);
            JsonMapper.ToJson(Value, w);
        }
    }
}