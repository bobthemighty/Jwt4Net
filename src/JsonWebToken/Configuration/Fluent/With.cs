namespace Jwt4Net.Configuration.Fluent
{
    public static class With
    {
        public static IContainerConfig Default
        {
            get { return new DefaultContainerConfig(); }
        }
    }
}