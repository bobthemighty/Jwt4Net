using System.IO;
using System.Security.Cryptography;
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
}