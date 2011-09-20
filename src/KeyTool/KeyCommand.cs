using System.IO;

namespace KeyTool
{
    public interface KeyCommand
    {
        int Execute();
        void WriteDescription(TextWriter stream);
        void WriteHelp(TextWriter stream);
        KeyCommand FromArgs(string[] args);
    }
}