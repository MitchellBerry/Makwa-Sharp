using Makwa;
using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Testing
{
    [TestClass]
    public class KATs
    {
        readonly static string katurl = "https://raw.githubusercontent.com/bsdphk/PHC/master/Makwa/kat.txt";
        readonly static string katpath = "kat.txt";
        KnownAnswerTests kats = ParseKATFile();
        Hasher makwa = new Hasher();

        /// Test parameters
        /// Modulus n as given, page 45, https://www.bolet.org/makwa/makwa-spec-20150422.pdf
        readonly byte[] n = Tools.HexStringToByteArray(
            "C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C2594" +
            "14A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA" +
            "14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2CE86F3490F49" +
            "93B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550" +
            "BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C" +
            "1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A189E73CE8E311D" +
            "3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E67428FC18F" +
            "B013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761" );

        [TestMethod]
        public void TestKDF256()
        {
            bool outcome = TestKDF(new HMACSHA256(), kats.KDF256);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void TestKDF512()
        {
            bool outcome = TestKDF(new HMACSHA512(), kats.KDF512);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA256DigestWorkFactor384()
        {
            bool outcome = TestDigest(new HMACSHA256(), 384, kats.ModSHA256);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA256DigestWorkFactor4096()
        {
            bool outcome = TestDigest(new HMACSHA256(), 4096, kats.ModSHA256);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA512DigestWorkFactor384()
        {
            bool outcome = TestDigest(new HMACSHA512(), 384, kats.ModSHA512);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA512DigestWorkFactor4096()
        {
            bool outcome = TestDigest(new HMACSHA512(), 4096, kats.ModSHA512);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA256HashPassword384()
        {
            bool outcome = TestHashPassword(new HMACSHA256(), 384, kats.ModSHA256);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA256HashPassword4096()
        {
            bool outcome = TestHashPassword(new HMACSHA256(), 4096, kats.ModSHA256);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA512HashPassword384()
        {
            bool outcome = TestHashPassword(new HMACSHA512(), 384, kats.ModSHA512);
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void SHA512HashPassword4096()
        {
            bool outcome = TestHashPassword(new HMACSHA512(), 4096, kats.ModSHA512);
            Assert.IsTrue(outcome);
        }

        bool TestKDF(HMAC hashfunction, List<Dictionary<String, String>> kats)
        {
            makwa.Hashfunction = hashfunction;
            makwa.Modulus = n;
            bool outcome = false;
            int testcounter = 0;
            foreach (Dictionary<string, string> kdfkat in kats)
            {
                string expected = kdfkat["output"];
                byte[] inputbytes = Tools.HexStringToByteArray(kdfkat["input"]);
                string result = BitConverter.ToString(makwa.KDF(inputbytes, 100)).Replace("-", "");
                if (expected == result.ToLower())
                {
                    outcome = true;
                    testcounter++;
                }
                else
                {
                    outcome = false;
                    break;
                }
            }
            Trace.WriteLine(testcounter + " KDF Known Answer Tests passed");
            return outcome;
        }

        bool TestDigest(HMAC hashfuction, uint workfactor, List<Dictionary<String, String>> kats)
        {
            makwa.Hashfunction = hashfuction;
            makwa.Workfactor = workfactor;
            makwa.Modulus = n;
            bool outcome = false;
            int testcounter = 0;
            foreach (Dictionary<string, string> digestkat in kats)
            {

                byte[] input = Tools.HexStringToByteArray(digestkat["input"]);
                byte[] salt = Tools.HexStringToByteArray(digestkat["salt"]);
                makwa.Prehashing = Convert.ToBoolean(digestkat["pre-hashing"]);
                if (digestkat["post-hashing"] == "false")
                {
                    makwa.Posthashing = 0;
                }
                else
                {
                    makwa.Posthashing = Convert.ToUInt16(digestkat["post-hashing"]);
                }

                string binstring = "bin" + workfactor;
                byte[] digestexpected = Tools.HexStringToByteArray(digestkat[binstring]);                
                byte[] result = makwa.Digest(input, salt);

                if (digestexpected.SequenceEqual<byte>(result))
                {
                    outcome = true;
                }
                else
                {
                    WriteTestTraces(testcounter, digestkat["input"], digestkat["bin384"], BitConverter.ToString(result));
                    outcome = false;
                    break;
                }
                testcounter++;

                if (testcounter > 100) { break; }
            }
            return outcome;
        }

        bool TestHashPassword(HMAC hashfunction, uint workfactor, List<Dictionary<String, String>> kats)
        {
            makwa.Hashfunction = hashfunction;
            makwa.Workfactor = workfactor;
            bool outcome = false;
            int testcounter = 0;
            foreach (Dictionary<string, string> digestkat in kats)
            {

                byte[] input = Tools.HexStringToByteArray(digestkat["input"]);
                byte[] salt = Tools.HexStringToByteArray(digestkat["salt"]);
                makwa.Prehashing = Convert.ToBoolean(digestkat["pre-hashing"]);
                if (digestkat["post-hashing"] == "false")
                {
                    makwa.Posthashing = 0;
                }
                else
                {
                    makwa.Posthashing = Convert.ToUInt16(digestkat["post-hashing"]);
                }

                string stringoutput = "str" + workfactor;
                string digestexpected = digestkat[stringoutput];
                makwa.Modulus = n;
                string result = makwa.HashPassword(input, salt);

                if (digestexpected == result)
                {
                    outcome = true;
                }
                else
                {
                    WriteTestTraces(testcounter, digestkat["input"], digestkat["bin384"], result);
                    outcome = false;
                    break;
                }
                testcounter++;

                if (testcounter > 100) { break; }
            }
            return outcome;
        }

        void WriteTestTraces(int testcounter, string input, string expected, string result)
        {
            Trace.WriteLine("Tests Run Before Failure: " + testcounter);
            Trace.WriteLine("Pre: " + makwa.Prehashing);
            Trace.WriteLine("Post: " + makwa.Posthashing);
            Trace.WriteLine("Input: " + input);
            Trace.WriteLine("Result: " + expected);
            Trace.WriteLine("Expected bin384: " + result);
        }

        public class KnownAnswerTests
        {
            public List<Dictionary<String, String>> KDF256 = new List<Dictionary<String, String>>();
            public List<Dictionary<String, String>> KDF512 = new List<Dictionary<String, String>>();
            public List<Dictionary<String, String>> ModSHA256 = new List<Dictionary<String, String>>();
            public List<Dictionary<String, String>> ModSHA512 = new List<Dictionary<String, String>>();
        }

        public static KnownAnswerTests ParseKATFile()
        {
            try
            {
                if (!File.Exists(katpath))
                {
                    using (WebClient client = new WebClient())
                    {
                        client.DownloadFile(katurl,"kat.txt");
                    }
                }
                string[] lines = File.ReadAllLines(katpath);
                KnownAnswerTests KATs = new KnownAnswerTests();

                // Initialise regexes
                Regex kdf256regex = new Regex("KDF/SHA-256");
                Regex kdf512regex = new Regex("KDF/SHA-512");
                Regex modSHA256initregex = new Regex("2048-bit modulus, SHA-256");
                Regex modSHA512initregex = new Regex("2048-bit modulus, SHA-512");
                Regex modSHA256regex = new Regex(@"2048-bit modulus, SHA-256 input: ([a-f0-9]*)" +
                    " salt: ([a-f0-9]*) pre-hashing: (.*) post-hashing: (.*) bin384: ([a-f0-9]*)" +
                    " bin4096: ([a-f0-9]*) str384: ([A-Za-z0-9+/_]*) str4096: ([A-Za-z0-9+/_]*)");
                Regex modSHA512regex = new Regex(@"2048-bit modulus, SHA-512 input: ([a-f0-9]*)" +
                    " salt: ([a-f0-9]*) pre-hashing: (.*) post-hashing: (.*) bin384: ([a-f0-9]*)" +
                    " bin4096: ([a-f0-9]*) str384: ([A-Za-z0-9+/_]*) str4096: ([A-Za-z0-9+/_]*)");

                // Parse lines, seperate KATs into appropriate lists of dictionaries
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];

                    // Check KAT type
                    if (kdf256regex.Match(line).Success)
                    {
                        var dict = new Dictionary<string, string>
                        {
                            { "input", lines[i + 1].Replace("input: ", string.Empty) },
                            { "output", lines[i + 2].Replace("output: ", string.Empty) }
                        };
                        KATs.KDF256.Add(dict);
                    }

                    else if (kdf512regex.Match(line).Success)
                    {
                        var dict = new Dictionary<string, string>
                        {
                            { "input", lines[i + 1].Replace("input: ", string.Empty) },
                            { "output", lines[i + 2].Replace("output: ", string.Empty) }
                        };
                        KATs.KDF512.Add(dict);
                    }

                    else if (modSHA256initregex.Match(line).Success)
                    {
                        // Concatenate variables and extract regex captures
                        String concat = String.Join(" ", lines.Skip(i).Take(9));
                        Match ModSHA256Match = modSHA256regex.Match(concat);

                        if (ModSHA256Match.Success)
                        {
                            var dict = new Dictionary<string, string>();
                            dict.Add("hashfunction", "SHA256");
                            dict.Add("input", ModSHA256Match.Groups[1].ToString());
                            dict.Add("salt", ModSHA256Match.Groups[2].ToString());
                            dict.Add("pre-hashing", ModSHA256Match.Groups[3].ToString());
                            dict.Add("post-hashing", ModSHA256Match.Groups[4].ToString());
                            dict.Add("bin384", ModSHA256Match.Groups[5].ToString());
                            dict.Add("bin4096", ModSHA256Match.Groups[6].ToString());
                            dict.Add("str384", ModSHA256Match.Groups[7].ToString());
                            dict.Add("str4096", ModSHA256Match.Groups[8].ToString());
                            KATs.ModSHA256.Add(dict);
                        }
                    }

                    else if (modSHA512initregex.Match(line).Success)
                    {
                        String concat = String.Join(" ", lines.Skip(i).Take(9));
                        Match ModSHA512Match = modSHA512regex.Match(concat);
                        if (ModSHA512Match.Success)
                        {
                            var dict = new Dictionary<string, string>();
                            dict.Add("hashfunction", "SHA512");
                            dict.Add("input", ModSHA512Match.Groups[1].ToString());
                            dict.Add("salt", ModSHA512Match.Groups[2].ToString());
                            dict.Add("pre-hashing", ModSHA512Match.Groups[3].ToString());
                            dict.Add("post-hashing", ModSHA512Match.Groups[4].ToString());
                            dict.Add("bin384", ModSHA512Match.Groups[5].ToString());
                            dict.Add("bin4096", ModSHA512Match.Groups[6].ToString());
                            dict.Add("str384", ModSHA512Match.Groups[7].ToString());
                            dict.Add("str4096", ModSHA512Match.Groups[8].ToString());
                            KATs.ModSHA512.Add(dict);
                        }
                    }

                    //string[] katKeys = { "input", "salt", "pre-hashing", "post-hashing", "bin384", "bin4096", "str384", "str4096" };
                    //var dict = new Dictionary<string, string>{{ "hashfunction", "SHA512" } };
                    //for (int j = 0; i < 8; i++ )
                    //{
                    //    dict.Add(katKeys[j], ModSHA512Match.Groups[j+1].ToString()); )
                    //}


                }
                return KATs;
            }
            catch (FileNotFoundException)
            {
                throw new FileNotFoundException("No KAT file and unable to download," +
                    " kat.txt can be found here:" +
                    " https://github.com/bsdphk/PHC/blob/master/Makwa/kat.txt. " +
                    "Place in KnownAnswerTests folder");
            }

        }

        // Pops out random know answer tests from the list, max number is 1000
        public KnownAnswerTests RandomKATsSubset(KnownAnswerTests kats, uint subsetLength = 200)
        {
            if (subsetLength >= 2000)
            {
                throw new ArgumentOutOfRangeException("Maximum number of KATs available is 2000");
            }
            subsetLength = 2000 - subsetLength;
            Random rnd = new Random();
            for (int i = 0; i < subsetLength; i++)
            {
                kats.ModSHA256.RemoveAt(rnd.Next(kats.ModSHA256.Count));
                kats.ModSHA512.RemoveAt(rnd.Next(kats.ModSHA512.Count));
            }
            return kats;
        }

        Dictionary<string, string> CreateKATDictionary(string hashfunction, Match regexMatch, int index)
        {
            string[] katKeys = { "input", "salt", "pre-hashing", "post-hashing", "bin384", "bin4096", "str384", "str4096" };
            var dict = new Dictionary<string, string> { { "hashfunction", hashfunction } };
            for (int j = 0; index < 8; index++)
            {
                dict.Add(katKeys[j], regexMatch.Groups[j + 1].ToString());
            }
            return dict;
    }
    }
}
