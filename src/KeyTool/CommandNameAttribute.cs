using System;

namespace KeyTool
{
    internal class CommandNameAttribute : Attribute
    {
        private readonly string[] _names;

        public CommandNameAttribute(params string[] names)
        {
            _names = names;
        }

        public string[] Names
        {
            get {
                return _names;
            }
        }
    }
}