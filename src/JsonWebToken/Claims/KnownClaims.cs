using Jwt4Net.Claims;
using LitJson;

namespace Jwt4Net
{
    public class KnownClaims
    {
       private static void Foo(UnixTimeStamp obj, JsonWriter writer)
        {
            writer.Write(obj.Value);
        }

        static KnownClaims()
        {
            JsonMapper.RegisterExporter<UnixTimeStamp>(Foo);
        }

        public static ClaimDescriptor<string> Issuer
        {
            get
            {
                return new ClaimDescriptor<string>("iss");
            }
        }

        public static ClaimDescriptorBase<UnixTimeStamp> Expiry
        {
            get { return new ExpiryClaimDescriptor(); }
        }

        internal class ExpiryClaimDescriptor : ClaimDescriptorBase<UnixTimeStamp>
        {
            public ExpiryClaimDescriptor() : base("exp")
            {
            }

            protected override IClaim<UnixTimeStamp> ReadImpl(JsonData source)
            {
                var value = source[Name];
                if (value.IsInt)
                    return new ExpiryClaim((int) value);
                if(value.IsLong)
                    return new ExpiryClaim((long)value);
                throw new JsonException(value + " is not an numeric data type");
            }
        }
        internal class ExpiryClaim : IClaim<UnixTimeStamp>
        {
            public ExpiryClaim(long value)
            {
                Value = new UnixTimeStamp(value);
            }

            public void Serialize(JsonWriter w)
            {
                w.Write(Value.Value);
            }

            public UnixTimeStamp Value
            {
                get;
                private set;
            }

            public string Name
            {
                get { return "exp"; }
            }
        }
    }


}
