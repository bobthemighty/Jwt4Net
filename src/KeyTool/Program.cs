using System;
using System.IO;
using System.Linq;
using NDesk.Options;

namespace KeyTool
{
    public class Program
    {
        public static int Main(string[] args)
        {
            return GetCommand(args).Execute();
        }

        private static KeyCommand GetCommand(string[] args)
        {
            string cmdName = string.Empty;
            if (args.Length > 0)
                cmdName = args[0];

            switch(cmdName)
            {
                case "":
                    return new CommandLister(args);
                case "gen":
                    return new GenerateKey(args);
                case "rm":
                    return new DeleteKey(args);
                default:
                    return new CommandLister(args);
            }
        }
    }

    internal class CommandLister : KeyCommand
    {
        private readonly string[] _args;

        public CommandLister(string[] args)
        {
            _args = args; 
        }

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
                var cmd = Activator.CreateInstance(t, new object[]{_args}) as KeyCommand;
                cmd.WriteDescription(Console.Out);
            }

        }
    }

    public interface KeyCommand
    {
        int Execute();
        void WriteDescription(TextWriter stream);
        void WriteHelp(TextWriter stream);
    }

    internal class CommandNameAttribute : Attribute
    {
        private readonly string[] _names;

        public CommandNameAttribute(params string[] names)
        {
            _names = names;
        }
    }
}
