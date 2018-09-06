using System;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using System.Runtime.Serialization;

namespace Makwa
{


    public class Tools
    {
        public static byte[] I2OSP(BigInteger x)
        {
            return I2OSP(x, x);
        }

        public static byte[] I2OSP(BigInteger x, BigInteger modulus)
        {
            int len = (modulus.BitLength + 7) >> 3;
            byte[] b = x.ToByteArray();
            int blen = b.Length;
            if (blen < len)
            {
                byte[] nb = new byte[len];
                Array.Copy(b, 0, nb, len - blen, blen);
                return nb;
            }
            else if (blen == len)
            {
                return b;
            }
            else
            {
                byte[] nb = new byte[len];
                Array.Copy(b, blen - len, nb, 0, len);
                return nb;
            }

        }

        public static BigInteger OS2IP(byte[] b, BigInteger modulus)
        {
            int len = (modulus.BitLength + 7) >> 3;
            int blen = b.Length;
            if (blen != len)
            {
                throw new ArgumentOutOfRangeException("Invalid integer input");
            }
            if (b[0] < 0)
            {
                byte[] nb = new byte[blen + 1];
                Array.Copy(b, 0, nb, 1, blen);
                b = nb;
            }
            BigInteger x = new BigInteger(1, b);
            if (x.CompareTo(modulus) >= 0)
            {
                throw new ArgumentOutOfRangeException("Invalid integer input");
            }
            return x;
        }

        public static string DecodeBase64(byte[] m)
        {
            return Convert.ToBase64String(m).Replace("=", "");
        }

        public static byte[] EncodeBase64(string m)
        {
            //int len = ((4 - (m.Length % 4) % 4));
            int len = (m.Length % 4);
            string padding = new string('=', len);
            return Convert.FromBase64String(m + padding);
        }

        public static byte[] HexStringToByteArray(String hexstring)
        {
            int NumberChars = hexstring.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hexstring.Substring(i, 2), 16);
            return bytes;
        }

        public static bool ConstantTimeComparison(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (uint i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        public static bool InvalidWorkfactor(uint workfactor)
        {
            if (workfactor == 0) { return true; }
            bool checkthree = IsPowerofTwo(workfactor / 3);
            bool checktwo = IsPowerofTwo(workfactor / 2);
            return (!(checkthree || checktwo));
        }

        static bool IsPowerofTwo(uint x)
        {
            return (x != 0) && ((x & (x - 1)) == 0);
        }

        public static uint SuggestWorkFactor(uint workFactor)
        {
            uint[] validWorkFactors = { 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
                768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
                65536, 98304, 131072, 196608, 262144, 393216, 524288, 786432, 1048576, 1572864 };
            uint[] distances = new uint[validWorkFactors.Length];
            uint smallestDistance = 1572864;
            uint closestValidWorkFactor = 1572864;
            uint distance = new int();
            for (int i = 0; i < validWorkFactors.Length; i++)
            {
                distance = (uint)Math.Abs(validWorkFactors[i] - workFactor);
                if (distance < smallestDistance)
                {
                    smallestDistance = distance;
                    closestValidWorkFactor = validWorkFactors[i];
                }
            }
            return closestValidWorkFactor;
        }
    }

    public struct PasswordHashString
    {
        public string modulusChecksum;
        public string stateData;
        public byte[] salt;
        public string digest;
        private string _fullHash;
        public string fullHash
        {
            get
            {
                return _fullHash;
            }
            set
            {
                string[] values = value.Split('_');
                modulusChecksum = values[0];
                stateData = values[1];
                salt = Tools.EncodeBase64(values[2]);
                digest = values[3];
                _fullHash = value;
            }
        }
    }


    public class Hasher
    {
        public HMAC Hashfunction { get; set; } = new HMACSHA256();
        public uint Workfactor { get; set; } = 4096;
        public bool Prehashing { get; set; } = true;
        public ushort Posthashing { get; set; } = 12;
        private byte[] _Modulus;
        public byte[] Modulus
        {
            get
            {
                return _Modulus;
            }
            set
            {
                _Modulus = value;
                ModulusID = KDF(Modulus, 8);
                ModulusChecksum = Tools.DecodeBase64(ModulusID);
            }
        }
        public byte[] ModulusID { get; set; }
        public string ModulusChecksum { get; set; }

        public struct Params
        {
            public bool preHash { get; set; }
            public ushort postHashLength { get; set; }
            public uint workfactor { get; set; }
            public byte[] tau { get; set; }

        }

        public static Params ParseParams(PasswordHashString hashstring)
        {
            Params output = new Params();
            output.tau = Tools.EncodeBase64(hashstring.digest);
            string state = hashstring.stateData;
            output.workfactor = Convert.ToUInt32(state.Substring(1, 1));
            int wlHigh = Convert.ToInt16(state.Substring(2, 1));
            int wlLow = Convert.ToInt16(state.Substring(3, 1));
            int wl = 10 * wlHigh + wlLow;
            output.workfactor <<= wl;
            string hashFlag = state.Substring(0, 1);
            switch (hashFlag)
            {
                case "n":
                    output.preHash = false;
                    output.postHashLength = 0;
                    break;
                case "r":
                    output.preHash = true;
                    output.postHashLength = 0;
                    break;
                case "s":
                    output.preHash = false;
                    output.postHashLength = (ushort)output.tau.Length;
                    break;
                case "b":
                    output.preHash = true;
                    output.postHashLength = (ushort)output.tau.Length;
                    break;
                default:
                    throw new MakwaException("invalid Makwa output string");
            }
            return output;

        }

        bool InvalidModulus(PasswordHashString hashstring)
        {
            return hashstring.modulusChecksum != ModulusChecksum;
        }

        public bool VerifyPassword(string password, string hash)
        {
            PasswordHashString hashString = new PasswordHashString() { fullHash = hash };
            Params hashParams = ParseParams(hashString);
            // check modulus matchs, set hasher params
            if (InvalidModulus(hashString))
            {
                throw new Exception("Password modulus doesnt match hashher modulus");
            }
            Prehashing = hashParams.preHash;
            Posthashing = hashParams.postHashLength;
            Workfactor = hashParams.workfactor;

            // hash submitted password
            byte[] passwordDigest = Digest(password, hashString.salt);
            // constant time check
            bool match = Tools.ConstantTimeComparison(hashParams.tau, passwordDigest);
            return match;
        }
        

        public string HashPassword(string password)
        {
            return HashPassword(System.Text.Encoding.UTF8.GetBytes(password));
        }


        public string HashPassword(byte[] password, byte[] salt = null)
        {
            if (salt == null)
            {
                byte[] buffer = new byte[16];
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(buffer);
                salt = buffer;
            }
            if (salt.Length != 16)
            {
                throw new ArgumentOutOfRangeException("Salt must be 16 bytes long");
            }
            string statedata = GetStateData();
            string saltb64 = Tools.DecodeBase64(salt);
            string digest = Tools.DecodeBase64(Digest(password, salt));
            return CreateHashString(ModulusChecksum, statedata, saltb64, digest);
        }

        public byte[] Digest(string password, byte[] salt = null)
        {
            byte[] pwd = System.Text.Encoding.UTF8.GetBytes(password);
            return Digest(pwd, salt);
        }

        public byte[] Digest(byte[] password, byte[] salt = null)
        {
            if (Modulus == null)
            {
                throw new ArgumentNullException("No modulus provided");
            }
            int k = Modulus.Length;
            if (k < 160)
            {
                throw new ArgumentOutOfRangeException("Modulus must be greater than 160 bytes");
            }
            if (Tools.InvalidWorkfactor(Workfactor))
                {
                    uint suggested = Tools.SuggestWorkFactor(Workfactor);
                    throw new ArgumentOutOfRangeException("Closest valid workfactor: " + suggested + "" +
                        Environment.NewLine + "Workfactors restricted to  w = ζ · 2^δ, where ζ = 2 or 3, and δ ≥ 0");
                }
            if (Prehashing)
            {
                password = KDF(password, 64);
            }
            int u = password.Length;
            if (u > 255 || u > (k - 32))
            {
                throw new ArgumentOutOfRangeException("Password is too long to be hashed with these parameters");
            }
            byte[] ub = new byte[] { (byte)u };
            byte[] sb = KDF(ConcatenateByteArrays(salt, password, ub), k - 2 - u);
            byte[] zerobyte = new byte[] { 0 };
            byte[] xb = ConcatenateByteArrays(zerobyte, sb, password, ub);
            BigInteger x = new BigInteger(1, xb);
            BigInteger n = new BigInteger(1, Modulus);
            //string xhex = x.ToString(16);
            //string nhex = n.ToString(16);
            BigInteger y = ModularSquarings(x, Workfactor, n);
            byte[] Y = Tools.I2OSP(y, n);
            return PostHashing(Y);
        }

        byte[] PostHashing(byte[] Y)
        {
            if (Posthashing >= 10)
            {
                Y = KDF(Y, Posthashing);
            }
            else if (Posthashing != 0)
            {
                throw new ArgumentOutOfRangeException("PostHashing length must be at least 10 bytes long");
            }
            return Y;
        } 

        static BigInteger ModularSquarings(BigInteger v, uint wf, BigInteger mod)
        {
            BigInteger exp = new BigInteger("2");
            for (int i = 0; i <= wf; i++)
            {
                v = v.ModPow(exp, mod);
            }
            return v;
        }

        public string GetStateData()
        {
            string output = "";
            bool pre = Prehashing;
            bool post = Posthashing > 0;
            if (!pre && !post)      { output += "n"; }
            else if (pre && !post)  { output += "r"; }
            else if (!pre && post)  { output += "s"; }
            else                    { output += "b"; }
            int delta = 0;
            uint w = Workfactor;
            uint andResult = w & 1;
            while (andResult == 0)
            {
                delta += 1;
                w /= 2;
                andResult = w & 1;
            }
            if (w == 1)
            {
                output += "2";
                output += (delta - 1).ToString();
            }
            else
            {
                output += "3";
                output += delta.ToString().PadLeft(2, '0');
            }
            return output;
        }

        public byte[] KDF(byte[] data, int outLength)
        {
            if (!(Hashfunction is HMACSHA256 || Hashfunction is HMACSHA512))
            {
                throw new ArgumentOutOfRangeException("HashFunction can only be HMACSHA256 or HMACSHA512"); 
            }
            byte[] hexzero = new byte[] { 0x00 };
            byte[] hexone = new byte[] { 0x01 };
            int r = Hashfunction.HashSize / 8;
            byte[] V = CustomByteArray(0x01, r);
            byte[] K = CustomByteArray(0x00, r);
            HMAC hashbuffer = Hashfunction;
            hashbuffer.Key = K;
            byte[] hmacdata = ConcatenateByteArrays(V, hexzero, data);
            hashbuffer.Key = hashbuffer.ComputeHash(hmacdata);
            V = hashbuffer.ComputeHash(V);
            hashbuffer.Key = hashbuffer.ComputeHash(ConcatenateByteArrays(V, hexone, data));
            V = hashbuffer.ComputeHash(V);
            byte[] T = new byte[0];
            while (T.Length < outLength)
            {
                V = hashbuffer.ComputeHash(V);
                T = ConcatenateByteArrays(T, V);
            }
            byte[] output = new byte[outLength];
            Array.Copy(T, output, outLength);
            return output;
        }

        static byte[] CustomByteArray(byte custombyte, int length)
        {
            var arr = new byte[length];
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = custombyte;
            }
            return arr;
        }

        public static byte[] ConcatenateByteArrays(params byte[][] arrays)
        {
            int outLength = 0;
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                outLength += array.Length;
            }
            byte[] output = new byte[outLength];
            foreach (byte[] data in arrays)
            {
                Buffer.BlockCopy(data, 0, output, offset, data.Length);
                offset += data.Length;
            }
            return output;
        }

        static string CreateHashString(string moduluschecksum, string statedata, string salt, string digest)
        {
            return string.Join("_", new[] { moduluschecksum, statedata, salt, digest });
        }



        //public class Output
        //{

        //    private byte[] salt;
        //    private bool preHash;
        //    private int postHashLength;
        //    private int workFactor;
        //    private byte[] tau;
        //    private BigInteger tauInt;

        //    internal Output(string str)
        //    {
        //        // Get modulus ID and verify it.
        //        int j = str.IndexOf('_');
        //        if (j != 11)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }
        //        byte[] smod = Tools.DecodeBase64(str.Substring(0, j));

        //        if (false)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }
        //        str = str.Substring(j + 1);

        //        // Get flags & work factor.
        //        j = str.IndexOf('_');
        //        if (j != 4)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }
        //        char ht = str[0];
        //        switch (str[1])
        //        {
        //            case '2':
        //                workFactor = 2;
        //                break;
        //            case '3':
        //                workFactor = 3;
        //                break;
        //            default:
        //                throw new MakwaException("invalid Makwa output string");
        //        }
        //        int wlh = str[2] - '0';
        //        int wll = str[3] - '0';
        //        if (wlh < 0 || wlh > 9 || wll < 0 || wll > 9)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }
        //        int wl = 10 * wlh + wll;
        //        if (wl > 29)
        //        {
        //            throw new MakwaException("unsupported work factor (too large)");
        //        }
        //        workFactor <<= wl;
        //        str = str.Substring(j + 1);

        //        // Get salt.
        //        j = str.IndexOf('_');
        //        if (j < 0)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }
        //        salt = base64Decode(str.Substring(0, j), true, false);
        //        str = str.Substring(j + 1);

        //        // Get output.
        //        tau = base64Decode(str, true, false);
        //        if (tau.Length == 0)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }

        //        // Process flags.
        //        switch (ht)
        //        {
        //            case 'n':
        //                preHash = false;
        //                postHashLength = 0;
        //                break;
        //            case 'r':
        //                preHash = true;
        //                postHashLength = 0;
        //                break;
        //            case 's':
        //                preHash = false;
        //                postHashLength = tau.Length;
        //                break;
        //            case 'b':
        //                preHash = true;
        //                postHashLength = tau.Length;
        //                break;
        //            default:
        //                throw new MakwaException("invalid Makwa output string");
        //        }
        //        if (postHashLength == 0)
        //        {
        //            tauInt = Tools.OS2IP(tau);
        //        }
        //        else if (postHashLength < 10)
        //        {
        //            throw new MakwaException("invalid Makwa output string");
        //        }
        //        else
        //        {
        //            tauInt = null;
        //        }
        //    }

        //}
    }


    [Serializable]
    internal class MakwaException : Exception
    {
        public MakwaException()
        {
        }

        public MakwaException(string message) : base(message)
        {
        }

        public MakwaException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected MakwaException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}

