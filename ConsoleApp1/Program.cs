using System;
using Makwa;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Globalization;
using System.Numerics;
using CommandLine;
using CommandLine.Text;
using System.Collections.Generic;


namespace CLI
{
    class Program
    {

        static readonly string nhex = "C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C259414A01AC1D5" +
                "2E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5" +
                "EA02FC0CCAF96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550" +
                "BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C1DC57FCDEFACA6AB043F8E13F6C" +
                "0BE7B39C92DA86E1D87477A189E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E" +
                "67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761";
        readonly static byte[] n = Tools.HexStringToByteArray(nhex);

        static void Main()
        {
            
            //string[] args = new string[]{ "password with space", "-w", "1024", "-l", "12" };
            string[] args = Console.ReadLine().Split();
            //string[] args = new string[] { "-r0" };
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
