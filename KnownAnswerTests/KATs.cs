using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Makwa;
using System.Linq;
using System.Diagnostics;

namespace Testing
{
    [TestClass]
    public class KATs
    {
        [TestMethod]
        public void TestKDF256()
        {
            KnownAnswerTests kats = ParseKATFile();
            bool outcome = false;
            int counter = 0;
            foreach (Dictionary<string,string> kdf256kat in kats.KDF256)
            {
                Hasher hasher = new Hasher();
                string expected = kdf256kat["output"];
                byte[] inputbytes = Tools.HexStringToByteArray(kdf256kat["input"]);
                string result = BitConverter.ToString(hasher.KDF(inputbytes, 100)).Replace("-","");
                if (expected == result.ToLower())
                {
                    outcome = true;
                    counter++;
                }
                else
                {
                    outcome = false;
                    break;
                }
            }
            Trace.WriteLine("Tested " + counter + " SHA256 KDF Known Anser Tests");
            Assert.IsTrue(outcome);

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

                // Parse lines, seperate KATs into dictionaries based on type
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];

                    // Check KAT type
                    if (KDF256regex.Match(line).Success)
                    {
                        var dict = new Dictionary<string, string>();
                        dict.Add("input", lines[i + 1].Replace("input: ", string.Empty));
                        dict.Add("output", lines[i + 2].Replace("output: ", string.Empty));
                        KATs.KDF256.Add(dict);
                    }

                    else if (KDF512regex.Match(line).Success)
                    {
                        var dict = new Dictionary<string, string>();
                        dict.Add("input", lines[i + 1].Replace("input: ", string.Empty));
                        dict.Add("output", lines[i + 2].Replace("output: ", string.Empty));
                        KATs.KDF512.Add(dict);
                    }

                    else if (modSHA256initialregex.Match(line).Success)
                    {
                        // Concatenate variables and extract with regex captures
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
                        // Concatenate variables and extract with regex captures
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
                }
                return KATs;
            }
            catch (System.IO.FileNotFoundException)
            {
                throw new System.IO.FileNotFoundException("No KAT file");
            }


        }
    }

    class Parsing
    {
        
    }
}
