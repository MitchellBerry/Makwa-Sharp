using Makwa;
using System;
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
        KnownAnswerTests kats = ParseKATFile();
        Hasher hasher = new Hasher();
        static string nhex = "C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C259414A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A189E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761";
        byte[] n = Tools.HexStringToByteArray(nhex);

        [TestMethod]
        public void TestKDF256()
        {
            //hasher.Hashfunction = new HMACSHA256();
            bool outcome = false;
            int testcounter = 0;
            foreach (Dictionary<string,string> kdf256kat in kats.KDF256)
            {
                string expected = kdf256kat["output"];
                byte[] inputbytes = Tools.HexStringToByteArray(kdf256kat["input"]);
                string result = BitConverter.ToString(hasher.KDF(inputbytes, 100)).Replace("-","");
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
            Trace.WriteLine(testcounter + " SHA256 KDF Known Answer Tests passed");
            Assert.IsTrue(outcome);
        }
        
        [TestMethod]
        public void TestKDF512()
        {
            hasher.Hashfunction = new HMACSHA512();
            bool outcome = false;
            int testcounter = 0;
            foreach (Dictionary<string, string> kdf512kat in kats.KDF512)
            {
                string expected = kdf512kat["output"];
                byte[] inputbytes = Tools.HexStringToByteArray(kdf512kat["input"]);
                string result = BitConverter.ToString(hasher.KDF(inputbytes, 100)).Replace("-", "");
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
            Trace.WriteLine(testcounter + " SHA512 KDF Known Answer Tests passed");
            Assert.IsTrue(outcome);
        }

        [TestMethod]
        public void TestModSHA256Digest()
        {
            hasher.Hashfunction = new HMACSHA256();
            bool outcome = false;
            int testcounter = 0;
            foreach (Dictionary<string, string> sha256kat in kats.ModSHA256)
            {
                byte[] input = Tools.HexStringToByteArray(sha256kat["input"]);
                byte[] salt = Tools.HexStringToByteArray(sha256kat["salt"]);
                hasher.Prehashing = Convert.ToBoolean(sha256kat["pre-hashing"]);
                if (sha256kat["post-hashing"] == "false")
                {
                    hasher.Posthashing = 0;
                }
                else
                {
                    hasher.Posthashing = Convert.ToInt32(sha256kat["post-hashing"]);
                }
                byte[] digestexpected384 = Tools.HexStringToByteArray(sha256kat["bin384"]);
                byte[] digestexpected4096 = Tools.HexStringToByteArray(sha256kat["bin4096"]);

                hasher.Workfactor = 384;
                byte[] result384 = hasher.Digest(input, n, salt);
                Assert.AreEqual(digestexpected384, result384);

                hasher.Workfactor = 4096;
                byte[] result4096 = hasher.Digest(input, n, salt);
                Assert.AreEqual(digestexpected4096, result384);
                testcounter++;
                if (testcounter > 10)
                {
                    break;
                }
                
            }
        }

        public class KnownAnswerTests
        {
            public List<Dictionary<String, String>> KDF256 = new List<Dictionary<String, String>>();
            public List<Dictionary<String, String>> KDF512 = new List<Dictionary<String, String>>();
            public List<Dictionary<String, String>> ModSHA256 = new List<Dictionary<String, String>>();
            public List<Dictionary<String, String>> ModSHA512 = new List<Dictionary<String, String>>();
        }

        public static KnownAnswerTests ParseKATFile(string filepath = "kat.txt")
        {
            try
            {
                // Read kat file
                string[] lines = System.IO.File.ReadAllLines(filepath);

                KnownAnswerTests KATs = new KnownAnswerTests();

                // Initialise regexes
                Regex KDF256regex = new Regex("KDF/SHA-256");
                Regex KDF512regex = new Regex("KDF/SHA-512");
                Regex modSHA256initialregex = new Regex("2048-bit modulus, SHA-256");
                Regex modSHA512initialregex = new Regex("2048-bit modulus, SHA-512");
                Regex modSHA256regex = new Regex(@"2048-bit modulus, SHA-256 input: ([a-f0-9]*) salt: ([a-f0-9]*) pre-hashing: (.*) post-hashing: (.*) bin384: ([a-f0-9]*) bin4096: ([a-f0-9]*) str384: ([A-Za-z0-9+/_]*) str4096: ([A-Za-z0-9+/_]*)");
                Regex modSHA512regex = new Regex(@"2048-bit modulus, SHA-512 input: ([a-f0-9]*) salt: ([a-f0-9]*) pre-hashing: (.*) post-hashing: (.*) bin384: ([a-f0-9]*) bin4096: ([a-f0-9]*) str384: ([A-Za-z0-9+/_]*) str4096: ([A-Za-z0-9+/_]*)");

                // Parse lines, seperate KATs into appropriate lists of dictionaries
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];

                    // Check KAT type
                    if (KDF256regex.Match(line).Success)
                    {
                        var dict = new Dictionary<string, string>
                        {
                            { "input", lines[i + 1].Replace("input: ", string.Empty) },
                            { "output", lines[i + 2].Replace("output: ", string.Empty) }
                        };
                        KATs.KDF256.Add(dict);
                    }

                    else if (KDF512regex.Match(line).Success)
                    {
                        var dict = new Dictionary<string, string>
                        {
                            { "input", lines[i + 1].Replace("input: ", string.Empty) },
                            { "output", lines[i + 2].Replace("output: ", string.Empty) }
                        };
                        KATs.KDF512.Add(dict);
                    }

                    else if (modSHA256initialregex.Match(line).Success)
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

                    else if (modSHA512initialregex.Match(line).Success)
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
            catch (System.IO.FileNotFoundException)
            {
                throw new System.IO.FileNotFoundException("No KAT file");
            }
        }
    }
}
