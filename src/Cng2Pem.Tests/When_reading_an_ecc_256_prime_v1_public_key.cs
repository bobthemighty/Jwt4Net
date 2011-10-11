using System.IO;
using System.Security.Cryptography;
using System.Text;
using Machine.Specifications;
using Penge;

namespace Cng2Pem.Tests
{
    public class When_reading_an_ecc_256_prime_v1_public_key
    {
        Establish context = () =>
                                {
                                    The_stream = File.OpenRead("pems\\ec-prime256v1-public.pem");
                                    The_reader = new PemReader(The_stream);
                                    _theBuilder = new CngBuilder(The_reader);
                                    the_data = Encoding.ASCII.GetBytes("\"bigdigsig\" ");

                                    using(var fs = File.OpenRead("pems\\ec-prim256r1.sig"))
                                    {
                                        theSignature = new byte[fs.Length];
                                        fs.Read(theSignature, 0, (int)fs.Length);
                                    }
                                };

        Because we_build_an_rsa_key = () => The_key = _theBuilder.Build();

        It should_return_an_emphemeral_key = () => The_key.IsEphemeral.ShouldBeTrue();
        It should_have_the_correct_algorithm_group = () => The_key.Algorithm.ShouldEqual(CngAlgorithm.ECDsaP256);
        It should_have_the_correct_key_size = () => The_key.KeySize.ShouldEqual(256);

        //TODO: Figure out how to convert an OpenSSL signature into a CNGKey signature. :(
//        It should_verify_the_sig = () =>
//                                               {
//                                                   var dsa = new ECDsaCng(The_key);
//                                                   dsa.VerifyData(the_data, theSignature).ShouldBeTrue();
//                                               };

        private Cleanup the_key = () =>
                                      {
                                          if (null != The_key)
                                              The_key.Dispose();
                                      };

        private static Stream The_stream;
        private static PemReader The_reader;
        private static CngBuilder _theBuilder;
        private static CngKey The_key;
        private static byte[] theSignature;
        private static byte[] the_data;
    }
}