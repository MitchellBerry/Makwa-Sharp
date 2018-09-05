using Makwa;
using System;
using System.IO;
using CommandLine;
using System.Text;
using Org.BouncyCastle.Math;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CLI
{
    class Program
    {
        static string filepath = "makwapublic.key";
        static BigInteger four = new BigInteger("4");
        static BigInteger three = new BigInteger("3");


        //static readonly string nhex = "C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C259414A01AC1D5" +
        //        "2E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5" +
        //        "EA02FC0CCAF96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550" +
        //        "BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C1DC57FCDEFACA6AB043F8E13F6C" +
        //        "0BE7B39C92DA86E1D87477A189E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E" +
        //        "67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761";
        //readonly static byte[] n = Tools.HexStringToByteArray(nhex);

        static void Main()
        {

            if (File.Exists(filepath))
            {
                byte[] publickey = File.ReadAllBytes(filepath);
                BigInteger modulus = MakwaPrivateKey.DecodePublic(publickey);
            }
            else
            {
                MakwaPrivateKey privateKey = MakwaPrivateKey.Generate(2048);
                byte[] publickey = privateKey.ExportPublic();
                BigInteger modulus = privateKey.Modulus;
                File.WriteAllBytes(filepath, publickey);
            }


            
            Console.WriteLine("Is probable prime: " + privateKey.p.IsProbablePrime(100));
            Console.WriteLine("3 mod 4: " + testBlumIntPrime(privateKey.p));
            Random rng = new Random();
            BigInteger possibleP = BigInteger.ProbablePrime(2048, rng);

            int counter = 0;
            while (testBlumIntPrime(possibleP))
            {
                counter++;
                Console.WriteLine(counter);
                possibleP = BigInteger.ProbablePrime(2048, rng);
            }

            string[] args = Console.ReadLine().Split();
            var options = new Options();
            var result = Parser.Default.ParseArguments<Options>(args);
            var resultParsed = result.WithParsed(opts => RunOptionsAndReturn(opts))
                .WithNotParsed(err => HandleParsingFailure(err));
            Console.ReadLine();
        }
        static int HandleParsingFailure(IEnumerable<Error> err)
        {
            Console.WriteLine(err);
            return 1;
        }

        static bool testBlumIntPrime(BigInteger prime)
        {
            return prime.Mod(four).Equals(three);
        }

        static int RunOptionsAndReturn(Options opts)
        {
            Hasher makwa = new Hasher();
            makwa.Prehashing = opts.Pre;
            makwa.Posthashing = opts.Post;
            makwa.Workfactor = opts.WorkFactor;
            if (opts.SHA512)
            {
                makwa.Hashfunction = new HMACSHA512();
            }
            else
            {
                makwa.Hashfunction = new HMACSHA256();
            }
            byte[] password = Encoding.UTF8.GetBytes(opts.Password);
            string passwordHash = makwa.HashPassword(password, n);
            Console.WriteLine(passwordHash);
            return 0;  
        }
    }

    class Options
    {
        [Value(0, MetaName = "Password", HelpText = "Password to be hashed", Required =true)]
        public string Password { get; set; }

        [Option('w', "work-factor", HelpText = "Number of iterations, higher provides more security with a time tradeoff")]
        public uint WorkFactor { get; set; }

        [Option('p', "pre", Default = false, HelpText = "Enables Pre-hashing of password")]
        public bool Pre { get; set; }

        [Option('l', "post",
        HelpText = "Post-Hashing length in bytes, reduces final hash size, set to 0 to get full length. Minimum is 10")]
        public ushort Post { get; set; }

        [Option('s', "sha512", Default = false, HelpText = "Uses SHA512 instead of SHA256 in the Key Derivation Function")]
        public bool SHA512 { get; set; }

    }
}
