namespace Jwt4Net.Signing
{
    public static class SigningAlgorithmExtensions
    {
        public static bool IsHmac(this SigningAlgorithm algorithm)
        {
            switch(algorithm)
            {
                case SigningAlgorithm.HS256:
                case SigningAlgorithm.HS384:
                case SigningAlgorithm.HS512:
                    return true;
                default:
                    return false;
            }
        }
    }
}