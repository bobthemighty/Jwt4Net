using System;
using System.IO;
using System.Linq;

namespace KeyTool
{
    [Command("list the commands available and display help information for commands.", "help", "?")]
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

        private static void WriteCommandHelp(string cmdName)
        {
            new CommandBuilder().GetCommand(cmdName, new string[0]).WriteHelp(Console.Out);
        }

        public void WriteHelp(TextWriter stream)
        {
            Type commandBaseType = typeof(KeyCommand);
            var types = GetType().Assembly.GetTypes().Where(t => commandBaseType.IsAssignableFrom(t) && t != commandBaseType);
            Console.WriteLine("\nKey tool: manage keys for Jwt4Net");
            Console.WriteLine("\tUsage keyTool.exe commandName [args]");
            Console.WriteLine("\n\tfor help use keytool help commandName\n");
            Console.WriteLine("\tAvailable commands:\n");

            foreach (var t in types)
            {
                var att = t.GetCustomAttributes(typeof (CommandAttribute), false).Cast<CommandAttribute>().First();
                var cmd = Activator.CreateInstance(t) as KeyCommand;
                var name = att.Names.First();
                Console.Out.WriteLine("\t" +name);
                if(att.Names.Count() > 1)
                Console.Out.WriteLine("\t\taliases: " + string.Join(", ", att.Names.Skip(1)));
                Console.Out.WriteLine("\t\t"+att.Description);
            }

        }

        public KeyCommand FromArgs(string[] args)
        {
            _args = args;
            return this;
        }
    }
}