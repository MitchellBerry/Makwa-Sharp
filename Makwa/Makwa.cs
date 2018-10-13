using System;
using Makwa.BigInt;
using System.Security.Cryptography;

namespace Makwa
{
    /// <summary>
    /// A complete hash string broken down into component parts
    /// </summary>
    public struct PasswordHashString
    {
        public string modulusChecksum;
        public string stateData;
        public byte[] salt;
        public string digest;
        private string _fullHash;
        public string FullHash
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

    /// <summary>
    /// Parameters used in the creation of a password hash
    /// </summary>
    public struct Params
    {
        public bool PreHash { get; set; }
        public ushort PostHashLength { get; set; }
        public uint Workfactor { get; set; }
        public byte[] Tau { get; set; }
    }

    /// <summary>
    /// Contains all the methods for the primary hashing, key derivation function
    /// and creating the formatted hash string
    /// </summary>
    public class Hasher
    {
        readonly byte[] hexzero = new byte[] { 0x00 };
        readonly byte[] hexone = new byte[] { 0x01 };
        public HMAC Hashfunction { get; set; } = new HMACSHA256();
        public uint Workfactor { get; set; } = 4096;
        public bool Prehashing { get; set; } = true;
        public ushort Posthashing { get; set; } = 12;
        RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
        public byte[] ModulusID { get; set; }
        public string ModulusChecksum { get; set; }
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

        
        public static Hasher Create(string moduluspath = null)
        {
            return new Hasher() { Modulus = FileIO.GetModulus(moduluspath) };
        }

        /// <summary>
        /// Parses a formatted hash string and extracts the parameters used to
        /// the create the hash
        /// </summary>
        /// 
        public static Params ParseParams(PasswordHashString hashstring)
        {
            // Add exceptions for invalid string parameters
            Params output = new Params();
            output.Tau = Tools.EncodeBase64(hashstring.digest);
            string state = hashstring.stateData;
            output.Workfactor = Convert.ToUInt32(state.Substring(1, 1));
            int wlHigh = Convert.ToInt16(state.Substring(2, 1));
            int wlLow = Convert.ToInt16(state.Substring(3, 1));
            int wl = 10 * wlHigh + wlLow;
            output.Workfactor <<= wl;
            string hashFlag = state.Substring(0, 1);
            switch (hashFlag)
            {
                case "n":
                    output.PreHash = false;
                    output.PostHashLength = 0;
                    break;
                case "r":
                    output.PreHash = true;
                    output.PostHashLength = 0;
                    break;
                case "s":
                    output.PreHash = false;
                    output.PostHashLength = (ushort)output.Tau.Length;
                    break;
                case "b":
                    output.PreHash = true;
                    output.PostHashLength = (ushort)output.Tau.Length;
                    break;
                default:
                    throw new Exception("invalid Makwa output string");
            }
            return output;

        }

        /// <summary>
        /// Confirms the modulus in a formatted hash string matches the
        /// one currently being used by the hasher
        /// </summary>
        bool InvalidModulus(PasswordHashString hashstring)
        {
            return hashstring.modulusChecksum != ModulusChecksum;
        }

        /// <summary>
        /// Verifies a given password against a formatted hash string, function uses 
        /// constant time byte comparison to protect against timing attacks.
        /// </summary>
        /// <param name="password">Password to verify</param>
        /// <param name="hash">A full formatted Makwa hash string</param>
        /// <returns>A boolean confirmation</returns>
        public bool VerifyPassword(string password, string hash)
        {
            PasswordHashString hashString = new PasswordHashString() { FullHash = hash };
            Params hashParams = ParseParams(hashString);
            if (InvalidModulus(hashString))
            {
                throw new ArgumentException("Password modulus doesnt match Hasher modulus");
            }
            Prehashing = hashParams.PreHash;
            Posthashing = hashParams.PostHashLength;
            Workfactor = hashParams.Workfactor;
            byte[] passwordDigest = Digest(password, hashString.salt);
            bool match = Tools.ConstantTimeComparison(hashParams.Tau, passwordDigest);
            return match;
        }

        /// <summary>
        /// The main Makwa hashing function which returns formatted hash string
        /// </summary>
        /// <remarks>
        /// Final output contains:
        /// <list type="bullet">
        /// <item>
        /// <description>Base64 modulus checksum</description>
        /// </item>
        /// <item>
        /// <description>Pre and Post hashing flags</description>
        /// </item>
        /// <item>
        /// <description>Workfactor used</description>
        /// </item>
        /// <item>
        /// <description>Base64 salt</description>
        /// </item>
        /// <item>
        /// <description>Base64 digest</description>
        /// </item>
        /// </list>
        /// This takes the form: 
        /// <code>B64(H8(N)) || “_” || F || “_” || B64(σ) || “_” || B64(τ)</code> 
        /// </remarks>
        /// <param name="password">The password to be hashed</param>
        /// <returns>A complete formatted Makwa hash string</returns>
        public string HashPassword(string password)
        {
            return HashPassword(System.Text.Encoding.UTF8.GetBytes(password));
        }

        /// <summary>
        /// The main Makwa hashing function which returns formatted hash string
        /// </summary>
        public string HashPassword(byte[] password, byte[] salt = null)
        {
            if (salt == null)
            {
                byte[] buffer = new byte[16];
                RNG.GetBytes(buffer);
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

        /// <summary>
        /// The raw hash digest function
        /// </summary>
        /// <param name="password">Password to be hashed</param>
        /// <param name="salt">(OPTIONAL) A user provided salt, must be 16 bytes long
        /// leave null for a securely generated random value</param>
        /// <returns>The digest bytes of the hashed password</returns>
        public byte[] Digest(string password, byte[] salt = null)
        {
            byte[] pwd = System.Text.Encoding.UTF8.GetBytes(password);
            return Digest(pwd, salt);
        }

        /// <summary>
        /// The raw hash digest function
        /// </summary>
        /// <param name="password">Password byte array to be hashed</param>
        /// <param name="salt">(OPTIONAL) A user provided salt, must be 16 bytes long
        /// leave null for a securely generated random value</param>
        /// <returns>The digest bytes of the hashed password</returns>
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
                    throw new ArgumentOutOfRangeException("Invalid workfactor, closest valid: " + suggested);
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
            BigInteger y = ModularSquarings(x, Workfactor, n);
            byte[] Y = Tools.I2OSP(y, n);
            return PostHashing(Y);
        }

        private byte[] PostHashing(byte[] Y) 
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

        /// <summary>
        /// Gets the current hashing parameters and formats them for inclusion
        /// in the HashPassword output
        /// </summary>
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

        /// <summary>
        /// Key derivation function, returns a hash of the specified length
        /// </summary>
        public byte[] KDF(byte[] data, int outLength)
        {
            if (!(Hashfunction is HMACSHA256 || Hashfunction is HMACSHA512))
            {
                throw new ArgumentOutOfRangeException("HashFunction can only be HMACSHA256 or HMACSHA512"); 
            }

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
    }
}

