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

            return new CommandBuilder().GetCommand(cmdName, args);
        }
    }
}
