using System;
using System.Linq;

namespace KeyTool
{
    public class CommandBuilder
    {
        public KeyCommand GetCommand(string commandName, string[] args)
        {
            var cmds = from t in GetType().Assembly.GetTypes().Where(typeof (KeyCommand).IsAssignableFrom) select t;
            var commandType =
                from c in cmds
                let att =c.GetCustomAttributes(typeof (CommandNameAttribute), false).FirstOrDefault() as CommandNameAttribute
                let names = (null == att) ? new string[0] : att.Names
                where names.Contains(commandName)
                select c;
            
            if(null == commandType.FirstOrDefault())
                return new CommandLister().FromArgs(args);

            var command = Activator.CreateInstance(commandType.FirstOrDefault()) as KeyCommand;
            return command.FromArgs(args);
        }
    }
}