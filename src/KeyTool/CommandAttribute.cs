using System;

namespace KeyTool
{
    internal class CommandAttribute : Attribute
    {
        public string Description { get; set; }
        private readonly string[] _names;

        public CommandAttribute(string description, params string[] names)
        {
            Description = description;
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