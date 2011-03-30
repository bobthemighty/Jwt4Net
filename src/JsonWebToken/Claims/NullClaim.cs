using LitJson;

namespace Jwt4Net.Claims
{
    public class NullClaim<T> : IClaim<T>
    {
        public NullClaim(string name)
        {
            Name = name;
        }

        public T Value
        {
            get { return default(T); }
        }

        public string Name
        {
            get;
            private set;
        }

        public void Serialize(JsonWriter w)
        {

        }
    }
}