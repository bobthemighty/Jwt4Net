using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Machine.Specifications;
using Penge;
using Security.Cryptography;

namespace Cng2Pem.Tests
{
    public class When_reading_an_rsa_public_key
    {
        Establish context = () =>
                                        {
                                            The_stream = File.OpenRead("pems\\rsa-1024-public.pem");
                                            The_reader = new PemReader(The_stream);
                                            _theBuilder = new CngBuilder(The_reader);
                                        };

        Because we_build_an_rsa_key = () => The_key = _theBuilder.Build();

        It should_return_an_emphemeral_key = () => The_key.IsEphemeral.ShouldBeTrue();
        It should_have_the_correct_algorithm_group = () => The_key.Algorithm.ShouldEqual(CngAlgorithm2.Rsa);
        It should_have_the_correct_key_size = () => The_key.KeySize.ShouldEqual(1024);


        private static Stream The_stream;
        private static PemReader The_reader;
        private static CngBuilder _theBuilder;
        private static CngKey The_key;
    }

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

    public class When_reading_pem_files
    {
        private Establish context = () =>
                                        {
                                            MyData =
                                                "-----BEGIN ROBOT ARMY PARAMS-----\n" +
                                                Convert.ToBase64String(
                                                    Encoding.UTF8.GetBytes("The Robot army is awesome")) + "\n" +
                                                "-----END ROBOT ARMY PARAMS-----" + "\n" +
                                                "-----BEGIN ROBOT ARMY-----" + "\n" +
                                                Convert.ToBase64String(Encoding.UTF8.GetBytes("Billy is a robot")) +"\n" +
                                                "-----END ROBOT ARMY-----";

                                            the_reader = new PemReader(new MemoryStream(ASCIIEncoding.Default.GetBytes(MyData)));
                                        };

        It should_have_robot_army_params = () => the_reader.First().Header.ShouldEqual("ROBOT ARMY PARAMS");
        It should_have_the_correct_body = () => the_reader.First().Body.ShouldContainOnly(Encoding.UTF8.GetBytes("The Robot army is awesome"));


        private static string MyData;
        private static PemReader the_reader;


    }

    internal class UTF8StringEncoding : IPayloadEncoding<string>
    {
        public string Decode(string payload)
        {
            var bytes = Convert.FromBase64String(payload);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
