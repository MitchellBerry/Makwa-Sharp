using Makwa;
using System;
using System.IO;
using CommandLine;
using Org.BouncyCastle.Math;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CLI
{
    class Program
    {
        static public string filepath = "modulus";
        static readonly BigInteger four = new BigInteger("4");
        static readonly BigInteger three = new BigInteger("3");

        static bool Keychecks(MakwaPrivateKey privateKey)
        {
            BigInteger p = privateKey.p;
            BigInteger q = privateKey.q;
            bool pprime = p.IsProbablePrime(150);
            bool qprime = q.IsProbablePrime(150);
            bool pblum = p.Mod(four).Equals(three);
            bool qblum = q.Mod(four).Equals(three);
            return pprime || qprime || pblum || qblum;
        }

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
            if (!(Keychecks(privateKey))) { throw new Exception("Prime Generation Error"); }
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
                Prehashing = opts.Pre,
                Posthashing = opts.Post,
                Workfactor = opts.WorkFactor
            };
            makwa.Modulus = GetModulus(opts.Modulus);
            if (opts.SHA512)
            {
                makwa.Hashfunction = new HMACSHA512();
            }
            else
            {
                makwa.Hashfunction = new HMACSHA256();
            }
            string passwordHash = makwa.HashPassword(opts.Password);
            Console.WriteLine(passwordHash);
            return 0;  
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
        public string HashString { get; set; }
    }
}
