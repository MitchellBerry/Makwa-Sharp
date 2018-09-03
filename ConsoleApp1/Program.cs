﻿using System;
using Makwa;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Globalization;
using System.Numerics;
using CommandLine;
using CommandLine.Text;


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
            string[] args = new string[]{ "password with space", "-w", "1024", "-l", "12" };

            //string[] args = new string[] { "-r0" };
            var options = new Options();
            var result = Parser.Default.ParseArguments<Options>(args);
            var resultParsed = result.WithParsed(opts => RunOptionsAndReturn(opts));
            
            //var resultNotParsed = result.WithNotParsed(err =>
            //{
            //    var helpText = HelpText.AutoBuild(result, h =>
            //    {
            //        // Configure HelpText here  or create your own and return it 
            //        h.AdditionalNewLineAfterOption = false;
            //        return HelpText.DefaultParsingErrorsHandler(result, h);
            //    }, e =>
            //    {
            //        return e;
            //    });
            //    Console.Error.Write(helpText);
            //});


            if (true)
            {
                // Values are available here
                //if (options.Pre) Console.WriteLine("Filename: {0}", options.InputFile);


            }

            Console.WriteLine(options.Pre);
            //Console.ReadLine();
        }

        //public static byte[] HexStringToByteArray(String hexstring)
        //{
        //    int NumberChars = hexstring.Length;
        //    byte[] bytes = new byte[NumberChars / 2];
        //    for (int i = 0; i < NumberChars; i += 2)
        //        bytes[i / 2] = Convert.ToByte(hexstring.Substring(i, 2), 16);
        //    return bytes;
        //}

        //public static byte[] HexToBytes(string hex)
        //{
        //    return Enumerable.Range(0, hex.Length)
        //                     .Where(x => x % 2 == 0)
        //                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
        //                     .ToArray();
        //}

        

        //static void Main(string[] args)
        //{

        //    //string password = "115aa3ec357ec71059a2eb347dc60f58a1ea337cc50e57a0e9327bc40d569fe8317ac30c559ee73079c20b549de62f78c10a539ce52e77c009529be42d76bf08519ae32c75be075099e22b74bd064f98e12a73bc054e97e02972bb044d96df2871ba034c95de2770b9024b94dd266fb8014a93dc256eb7004992db246db6ff4891da236cb5fe4790d9226bb4fd468fd8216ab3fc458e";
        //    //string salt = "b82cb42e3a2dfc2ad60b8b76c666b015";

        //    string password = "4765676F206265736877616A692761616B656E20617765206D616B77613B206F6E7A61616D206E616E69697A61616E697A692E";
            
        //    string salt = "C72703C22A96D9992F3DEA876497E392";
        //    BigInteger n = BigInteger.Parse("0" +"C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C259414A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A189E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761", NumberStyles.HexNumber);
        //    //BigInteger n = BigInteger.Parse("24512053064860435328877590242746522194209961194398407122042773656006062988700307054073145399569165851360439196611222687478427652709396958780621164892394715705596093579864582990357866004477891543023628255058292877490148860934813191606268325813495130876190991515957640217364020690938456594969566456205904775197538830354023844383853344580201096043911580777660138857736146026697875527572880314950221284315210268632715049507948071636182102885193688510547224429629170009832119151395279924498852891607394670000409094222424115272615353499274380194837556245470965824683643017008085343304399022796582902405557591416772081153889");
        //    // desired outcome 
        //    // +RK3n5jz7gs_s211_uCy0Ljot/CrWC4t2xmawFQ_+j6HFRMMfdstag

        //    //string password = "hunter2";
        //    //byte[] passbytes = Encoding.UTF8.GetBytes(password);

        //    Hasher makwa = new Hasher();
            
        //    //makwa.hashfunction = HMACSHA256.Create();
        //    byte[] saltbytes = HexStringToByteArray(salt);
        //    byte[] passbytes = HexStringToByteArray(password);

        //    makwa.Prehashing = false;
        //    makwa.Posthashing = 12;
        //    makwa.Workfactor =  4096;

        //    BigInteger v = BigInteger.Parse("60416251944245183801978395178840054874977954760974615244503738741779176414734020793524957222721696563186536630433065690145883126431908747587568069506465177744655382909492510275798681295316003651434368915041659697442795687818777029590671950459445346719119293403794067637730753985032608684421743299127914137922567225244001957429738746233394957053163356945709377309766948678520295670308338093400784819482286311024964430209091395952767337636468208836829392200618479562788786613982353919850393914601986179638607342261268302012008752944991889125431540930810349805980263071127162371754885909511446187766400203300971032115");
        //    BigInteger mod = BigInteger.Parse("24512053064860435328877590242746522194209961194398407122042773656006062988700307054073145399569165851360439196611222687478427652709396958780621164892394715705596093579864582990357866004477891543023628255058292877490148860934813191606268325813495130876190991515957640217364020690938456594969566456205904775197538830354023844383853344580201096043911580777660138857736146026697875527572880314950221284315210268632715049507948071636182102885193688510547224429629170009832119151395279924498852891607394670000409094222424115272615353499274380194837556245470965824683643017008085343304399022796582902405557591416772081153889");
        //    //BigInteger testmodpow = BigInteger.ModPow(v, 2, mod);
        //    //Console.WriteLine(testmodpow.ToString("X"));
        //    string nhex = "C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C259414A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A189E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761";
        //    byte[] n2 = HexStringToByteArray(nhex);
        //    string hashedpw = makwa.HashPassword(passbytes, n2, saltbytes);
        //    Console.WriteLine(hashedpw);
        //    //BigInteger thing = BigInteger.Parse("2");
        //    //Console.WriteLine(thing.ToString("X"));
        //    //Console.WriteLine(Encoding.ASCII.GetString(thing.ToByteArray()));
        //    //Console.WriteLine(BigInteger.ModPow(110, 13, 437));

        //    Console.WriteLine(BitConverter.ToString(Tools.DecodeUnpaddedBase64("uCy0Ljot/CrWC4t2xmawFQ")));

        //    //byte[] kdfinput = HexStringToByteArray("0e61");

        //    //byte[] kdfinput = HexStringToByteArray("2d80d32679cc1f72c5186bbe1164b70a5db00356a9fc4fa2f5489bee4194e73a8de03386d92c7fd22578cb");

        //    //byte[] kdftest = makwa.KDF(kdfinput, 10);
        //    //Console.WriteLine(BitConverter.ToString(kdftest).Replace("-", string.Empty));

        //    Console.Read();
        

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
        [Value(0, MetaName = "password", HelpText = "Password to be hashed")]
        public string Password { get; set; }


        [Option('w', "work-factor", Required = true, HelpText = "Number of iterations, higher provides more security with a time tradeoff")]
        public uint WorkFactor { get; set; }

        [Option('p', "pre", Default = false, HelpText = "Enables Pre-hashing of password")]
        public bool Pre { get; set; }

        [Option('l', "post",
        HelpText = "Post-Hashing length in bytes, reduces final hash size, set to 0 to get full length. Minimum size is 10")]
        public ushort Post { get; set; }

        [Option('s', "sha512", Default = false, HelpText = "Uses SHA512 instead of SHA256 in the Key Derivation Function")]
        public bool SHA512 { get; set; }


    }
}
