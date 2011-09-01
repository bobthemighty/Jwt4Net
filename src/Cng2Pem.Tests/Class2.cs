using System.IO;
using System.Security.Cryptography;
using System.Text;
using Machine.Specifications;
using Penge;

namespace Cng2Pem.Tests
{
    public class foo
    {
        private Establish context = () =>
                                        {
                                            The_stream = File.OpenRead("pems\\ec-prime256v1-public.pem");
                                            The_reader = new PemReader(The_stream);
                                            _theBuilder = new CngBuilder(The_reader);
                                            the_data = Encoding.ASCII.GetBytes("\"bigdigsig\" ");
                                            var dsa = new ECDsaCng(_theBuilder.Build());
                                            //the_sig = dsa.SignData(the_data);


                                            var otherKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
                                            var otherdsa = new ECDsaCng(otherKey);
                                            the_sig = otherdsa.SignData(the_data);
                                        };

        private Because the_data_is_signed = () =>
                                                 {

                                                 };

        private It should_not_die = () => the_sig.ShouldNotBeEmpty();

        private static Stream The_stream;
        private static PemReader The_reader;
        private static CngBuilder _theBuilder;
        private static CngKey The_key;
        private static byte[] theSignature;
        private static byte[] the_data;
        private static byte[] the_sig;
    }
}