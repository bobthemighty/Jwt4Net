using System;
using System.IO;
using System.Linq;

namespace KeyTool
{
    internal class CommandLister : KeyCommand
    {
        private string[] _args;

        public int Execute()
        {
            if (_args.Length == 2)
            {
                WriteCommandHelp(_args[1]);
                return 0;
            }
            WriteHelp(Console.Out);
            return 1;
        }

        private void WriteCommandHelp(string cmdName)
        {
            new CommandBuilder().GetCommand(cmdName, new string[0]).WriteHelp(Console.Out);
        }

        public void WriteDescription(TextWriter stream)
        {
            stream.WriteLine("\thelp - list the commands available and display help information for commands.");
        }

        public void WriteHelp(TextWriter stream)
        {
            Type commandBaseType = typeof(KeyCommand);
            var types = GetType().Assembly.GetTypes().Where(t => commandBaseType.IsAssignableFrom(t) && t != commandBaseType);
            Console.WriteLine("Key tool: manage keys for Jwt4Net");
            Console.WriteLine("\tUsage keyTool.exe commandName [args]");
            Console.WriteLine("for help use keytool help commandName");
            Console.WriteLine("\tAvailable commands:\n");

            foreach (var t in types)
            {
                var cmd = Activator.CreateInstance(t) as KeyCommand;
                cmd.WriteDescription(Console.Out);
            }

        }

        public KeyCommand FromArgs(string[] args)
        {
            _args = args;
            return this;
        }
    }
}