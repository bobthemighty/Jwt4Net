using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Machine.Specifications;
using Penge;

namespace Cng2Pem.Tests
{
    public class ecc_key_roundtrip_context
    {
        protected static CngKey The_original_key;
        protected static byte[] the_data;
        protected static CngKey The_roundtripped_key;
        protected static byte[] the_signature;
        protected static bool signature_is_valid;

        protected static void The_key_is(CngAlgorithm algorithm)
        {
            // create a new key pair
            The_original_key = CngKey.Create(algorithm);
            the_data = Encoding.UTF8.GetBytes("Hello world");

            // write the key pair to a stream in PEM format
            var ms = new MemoryStream();
            new PemWriter(ms).WritePublicKey(The_original_key);
            ms.Seek(0, SeekOrigin.Begin);

            // read the key back from the stream
            var builder = new CngBuilder(new PemReader(ms));
            The_roundtripped_key = builder.Build();
        }
    }

    public class When_using_a_roundtripped_ecc256_key : ecc_key_roundtrip_context
    {
        Establish context = () => The_key_is(CngAlgorithm.ECDsaP256);

        Because the_data_is_verified = () =>
                                           {
                                               the_signature = new ECDsaCng(The_original_key).SignData(the_data);
                                               signature_is_valid = new ECDsaCng(The_roundtripped_key).VerifyData(the_data, the_signature);
                                           };


        It should_be_valid = () => signature_is_valid.ShouldBeTrue();
    }

    public class When_using_a_roundtripped_ecc384key : ecc_key_roundtrip_context
    {
        Establish context = () => The_key_is(CngAlgorithm.ECDsaP384);

        Because the_data_is_verified = () =>
        {
            the_signature = new ECDsaCng(The_original_key).SignData(the_data);
            signature_is_valid = new ECDsaCng(The_roundtripped_key).VerifyData(the_data, the_signature);
        };


        It should_be_valid = () => signature_is_valid.ShouldBeTrue();
    }


    public class When_using_a_roundtripped_ecc521key : ecc_key_roundtrip_context
    {
        Establish context = () => The_key_is(CngAlgorithm.ECDsaP521);

        Because the_data_is_verified = () =>
        {
            the_signature = new ECDsaCng(The_original_key).SignData(the_data);
            signature_is_valid = new ECDsaCng(The_roundtripped_key).VerifyData(the_data, the_signature);
        };


        It should_be_valid = () => signature_is_valid.ShouldBeTrue();
    }
}