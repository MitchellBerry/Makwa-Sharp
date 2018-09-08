using Makwa;
using System;
using System.IO;
using Makwa.BigInt;
using CommandLine;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CLI
{
    class Program
    {
        static public string filepath = "modulus";
        static readonly BigInteger four = new BigInteger("4");
        static readonly BigInteger three = new BigInteger("3");

        static byte[] GetModulus(string path = null)
        {
            if (path == null) { path = filepath; }
            if (File.Exists(path))
            {
                try
                {
                     return File.ReadAllBytes(filepath);
                }
                catch (IOException)
                {
                    throw new IOException("Error Reading File: " + filepath);
                }
            }
            else
            {
                return CreateNewModulus();
            }
        }

        static byte[] CreateNewModulus(int length = 2048, string path = null)
        {
            MakwaPrivateKey privateKey = MakwaPrivateKey.Generate(length);
            byte[] modulus = Tools.I2OSP(privateKey.Modulus);
            if (path == null)
            {
                path = filepath;
            }
            WriteToFile(path, modulus);
            return modulus;
        }

        static void WriteToFile(string filepath, byte[] data)
        {
            try
            {
            File.WriteAllBytes(filepath, data);
            }
            catch (IOException)
            {
                throw new IOException("Error writing to file: " + filepath);
            }
        }
        
        static void Main()
        {

            string[] args = Console.ReadLine().Split();
            //string[] args = { "password", "-l", "12" };
            //string[] args = "pws -v VEwPfgcAews_s211_6Z/omBvD2q5bdzSJ9IgPAg_eGxAYvy8C3j3zsp/".Split(' ');
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

        static bool TestBlumIntPrime(BigInteger prime)
        {
            return prime.Mod(four).Equals(three);
        }

        static int RunOptionsAndReturn(Options opts)
        {
            Hasher makwa = new Hasher
            {
                Modulus = GetModulus(opts.Modulus),
                Prehashing = opts.Pre,
                Posthashing = opts.Post,
                Workfactor = opts.WorkFactor
            };
            if (opts.SHA512)
            {
                makwa.Hashfunction = new HMACSHA512();
            }
            else
            {
                makwa.Hashfunction = new HMACSHA256();
            }

            if (opts.VerifyString != null)
            {
                return Verify(makwa, opts);
            }

            string passwordHash = makwa.HashPassword(opts.Password);
            Console.WriteLine(passwordHash);
            return 0;  
        }

        static int Verify(Hasher makwa, Options opts)
        {
            bool match = makwa.VerifyPassword(opts.Password, opts.VerifyString);
            if (match)
            {
                Console.Write("True");
                return 0;
            }
            else
            {
                Console.Write("False");
                return 1;
            }
        }
    }



    class Options
    {
        [Value(0, MetaName = "Password", HelpText = "Password to be hashed", Required =true)]
        public string Password { get; set; }

        [Option('w', "work-factor", Default = (uint)4096, HelpText = "Number of iterations, higher provides more" +
            " security with a time tradeoff")]
        public uint WorkFactor { get; set; }

        [Option('p', "pre", Default = false, HelpText = "Enables Pre-hashing of password")]
        public bool Pre { get; set; }

        [Option('l', "post", Default = (ushort)12,
        HelpText = "Post-Hashing length in bytes, reduces final hash size, set to 0 to get" +
            " full length. Minimum is 10")]
        public ushort Post { get; set; }

        [Option('s', "sha512", Default = false, HelpText = "Uses SHA512 instead of SHA256 in the" +
            " Key Derivation Function")]
        public bool SHA512 { get; set; }

        [Option('m', "modulus", HelpText = "Specifies a filepath for" +
            " an encoded BigInteger modulus, returns an error if doesn't exist")]
        public string Modulus { get; set; }

        [Option('v', "verify", HelpText = "Will verify the password against a hash")]
        public string VerifyString { get; set; }
    }
}
