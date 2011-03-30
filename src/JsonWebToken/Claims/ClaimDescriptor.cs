using System;
using System.Collections.Generic;
using LitJson;

namespace Jwt4Net.Claims
{
    public interface IClaimDescriptor<T>
    {
        string Name { get; }
        IClaim<T> Read(JsonData source);
    }

    public abstract class ClaimDescriptorBase<T> : IClaimDescriptor<T>
    {
        internal ClaimDescriptorBase(string name)
        {
            Name = name;
        }

        protected ClaimDescriptorBase(Uri name)
        {
            Name = name.ToString();
        }

        public string Name
        {
            get;
            private set;
        }

        public IClaim<T> Read(JsonData source)
        {
            try
            {
                return ReadImpl(source);
            }
            catch (KeyNotFoundException)
            {
                return new NullClaim<T>(Name);
            }
        }

        protected abstract IClaim<T> ReadImpl(JsonData source);
    }

    public class ClaimDescriptor<T> : ClaimDescriptorBase<T>
    {
        internal ClaimDescriptor(string name) : base(name)
        {
        }

        public ClaimDescriptor(Uri name) : base(name)
        {
        }

        protected override IClaim<T> ReadImpl(JsonData source)
        {
            var target = typeof(T);

            if (target.IsPrimitive || target == typeof(Decimal) || target == typeof(String))
            {
                return BuildPrimitive(source, target);
            }

            return BuildCustomObject(source, target);
        }

        private IClaim<T> BuildPrimitive(JsonData source, Type target)
        {
            var token = source[Name];
            if (target == typeof(string))
            {
                if (token.IsString)
                    return new Claim<string>(Name, (String)token) as IClaim<T>;
            }

            if (target == typeof(int))
            {
                if (token.IsInt)
                {
                    return new Claim<int>(Name, (int)token) as IClaim<T>;
                }
            }

            return new NullClaim<T>(Name);
        }

        private IClaim<T> BuildCustomObject(JsonData source, Type target)
        {
            return
                new Claim<T>(Name,
                             JsonMapper.ToObject<T>(source[Name].ToJson()));
        }
    }
}