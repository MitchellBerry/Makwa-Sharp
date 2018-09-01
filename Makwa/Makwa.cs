using System;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;

namespace Makwa
{
    public class Tools
    {

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
            } else if (blen == len)
            {
                return b;
            } else
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
                throw new ArgumentOutOfRangeException("invalid integer input");
            }
            if (b[0] < 0)
            {
                byte[] nb = new byte[blen + 1];
                Array.Copy(b, 0, nb, 1, blen);
                b = nb;
            }
            BigInteger x = new BigInteger(1, b);
            if (x.CompareTo(modulus) >= 0) {
                throw new ArgumentException("invalid integer input");
            }
            return x;
        }

        public static string UnpaddedB64(byte[] m)
        {
            return Convert.ToBase64String(m).Replace("=", "");
        }

        public static byte[] Unbase64(string m)
        {
            int len = ((4 - (m.Length % 4) % 4));
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

        public static bool CheckWorkfactor(uint workfactor)
        {
            bool checkthree = IsPowerofTwo(workfactor / 3);
            bool checktwo = IsPowerofTwo(workfactor / 2);
            return checkthree || checktwo;
        }

        static bool IsPowerofTwo(uint x) 
        {
            return (x != 0) && ((x & (x - 1)) == 0);
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

    }

    public class Hasher
    {
        // Enforce attribute ranges, raise errors when out of range
        public HMAC Hashfunction { get; set; } = new HMACSHA256();
        public int Workfactor { get; set; } = 4096;
        public bool Prehashing { get; set; } = true;
        public int Posthashing { get; set; } = 12;

        public string HashPassword(byte[] password, byte[] n, byte[] salt = null)
        {
            // Salt argument for unit tests
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
            string moduluschecksum = Tools.UnpaddedB64(KDF(n, 8));
            string statedata = GetStateData();
            string saltb64 = Tools.UnpaddedB64(salt);
            byte[] digestresult = Digest(password, n, salt);
            string digestb64 = Tools.UnpaddedB64(digestresult);
            return CreateHashString(moduluschecksum, statedata, saltb64, digestb64);
        }

        public byte[] Digest(byte[] password, byte[] mod, byte[] salt)
        {
            int k = mod.Length;
            if (k < 160)
            {
                throw new ArgumentOutOfRangeException("Modulus must be greater than 160 bytes");
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
            BigInteger n = new BigInteger(1, mod);
            string xhex = x.ToString(16);
            string nhex = n.ToString(16);
            BigInteger y = ModularSquarings(x, Workfactor, n);
            byte[] Y = Tools.I2OSP(y, n);

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

        static BigInteger ModularSquarings(BigInteger v, int wf, BigInteger mod)
        {
            for (int i = 0; i <= wf; i++)
            {
                v = v.ModPow(new BigInteger("2"), mod);
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
            int w = Workfactor;
            int andResult = w & 1;
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
            byte[] hexzero = new byte[] { 0x00 };
            byte[] hexone = new byte[] { 0x01 };
            int r = Hashfunction.HashSize / 8;
            byte[] V = InitialiseCustomByteArray(0x01, r);
            byte[] K = InitialiseCustomByteArray(0x00, r);
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

        static byte[] InitialiseCustomByteArray(byte custombyte, int length)
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

