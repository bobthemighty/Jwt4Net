using System;
using System.IO;
using System.Linq;
using System.Text;
using Machine.Specifications;
using Penge;

namespace Cng2Pem.Tests
{
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

        It should_have_robot_army_params = () => ShouldExtensionMethods.ShouldEqual(the_reader.First().Header, "ROBOT ARMY PARAMS");
        It should_have_the_correct_body = () => ShouldExtensionMethods.ShouldContainOnly(the_reader.First().Body, Encoding.UTF8.GetBytes("The Robot army is awesome"));


        private static string MyData;
        private static PemReader the_reader;


    }
}