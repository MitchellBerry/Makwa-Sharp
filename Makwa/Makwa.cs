using System;
using System.Linq;
using System.Numerics;
//using System.Globalization;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Makwa
{
    public class Tools
    {
        //public static byte[] int_to_bytes(UInt64 i, int outlen = 0)
        //{
        //    byte[] bytes = BitConverter.GetBytes(i);
        //    //if (BitConverter.IsLittleEndian)
        //        //Array.Reverse(bytes);

        //    if (bytes.Length > outlen && outlen != 0)
        //    {
        //        byte[] trimmed_bytes = new byte[outlen];
        //        Array.Copy(bytes, trimmed_bytes, outlen);
        //        return trimmed_bytes;
        //    }
        //    return bytes;
        //}

        //public static byte[] SimpleBI2B(BigInteger x)
        //{
        //    // check if little endian
        //    byte[] array = x.ToByteArray();
        //    Array.Reverse(array, 0, array.Length);
        //    return array;
        //}

        //public static BigInteger SimpleB2BI(byte[] arr)
        //{
        //    //Array.Reverse(arr, 0, arr.Length);
        //    byte[] positivesignbyte = new byte[] { 00 };
        //    arr.Concat(positivesignbyte);
        //    BigInteger result = new BigInteger(arr);
        //    return result;
        //}

        //public static byte[] SimpleI2OSP(int x)
        //{
        //    // check if little endian
        //    byte[] array = BitConverter.GetBytes(x);
        //    //Array.Reverse(array, 0, array.Length);
        //    return array;
        //}

        //// I2OSP converts a non-negative integer to an octet string of a specified length.
        //// INT_TO_BYTE
        //public static byte[] I2OSP(BigInteger x, int size)
        //{
        //    byte[] array = x.ToByteArray();
        //    return I2OSP(array, size);
        //}

        //public static byte[] I2OSP(byte[] x, int size)
        //{
        //    Array.Reverse(x, 0, x.Length);
        //    byte[] result = new byte[size];
        //    Buffer.BlockCopy(x, 0, result, (result.Length - x.Length), x.Length);

        //    return result;
        //}

        //// PKCS #1 v.2.1, Section 4.2
        //// OS2IP converts an octet string to a nonnegative integer.
        //// BYTE_TO_INT
        //public static byte[] OS2IP(byte[] x)
        //{
        //    int i = 0;
        //    while ((x[i++] == 0x00) && (i < x.Length))
        //    {
        //        // confuse compiler into reporting a warning with {}
        //    }
        //    i--;
        //    if (i > 0)
        //    {
        //        byte[] result = new byte[x.Length - i];
        //        Buffer.BlockCopy(x, i, result, 0, result.Length);
        //        //Array.Reverse(result, 0, result.Length);
        //        return result;
        //    }
        //    else
        //        return x;
        //}

        public static byte[] I2OSP(byte[] x, int size)
        {
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(x, 0, x.Length);
            }
            byte[] result = new byte[size];
            Buffer.BlockCopy(x, 0, result, (result.Length - x.Length), x.Length);
            return result;
        }

        public static string UnpaddedBase64(byte[] m)
        {
            return Convert.ToBase64String(m).Replace("=", "");
        }

        public static byte[] unbase64(string m)
        {
            int len = ((4 - (m.Length % 4) % 4));
            string padding = new string('=', len);
            return Convert.FromBase64String(m + padding);
        }

    }

    public class Hasher
    {
        // Enforce attribute ranges, raise errors when out of range
        public HMAC hashfunction { get; set; } = new HMACSHA256();
        public int workfactor { get; set; } = 4096;
        public bool prehashing { get; set; } = true;
        public int posthashing { get; set; } = 12;

        //public string HashPassword(byte[] password, BigInteger n, byte[] salt)
        //{
        //    if (salt == null)
        //    {
        //        byte[] buffer = new byte[16];
        //        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        //        rng.GetBytes(buffer);
        //        salt = buffer;
        //    }

        //    string h = "";
        //    //byte[] checksum = KDF(Helpers.SimpleBI2B(n), 8);
        //    //string nhex = n.ToString("X");
        //    byte[] nArray = n.ToByteArray();
        //    byte[] checksum = KDF(Helpers.I2OSP(nArray, nArray.Length), 8);
        //    h += Helpers.base64(checksum);
        //    h += "_";
        //    h += GetStateData();
        //    h += "_";
        //    h += Helpers.base64(salt);
        //    h += "_";
        //    byte[] digestresult = Digest(password, n, salt);
        //    h += Helpers.base64(digestresult);
        //    return h;
        //}

        public string HashPassword2(byte[] password, byte[] n, byte[] salt = null)
        {
            // Salt variable availabe for tests, best practice is to leave null.
            if (salt == null)
            {
                byte[] buffer = new byte[16];
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(buffer);
                salt = buffer;
            }
            string h = "";
            h += Tools.UnpaddedBase64(KDF(n, 8));
            h += "_";
            h += GetStateData();
            h += "_";
            h += Tools.UnpaddedBase64(salt);
            h += "_";
            h += Tools.UnpaddedBase64(Digest(password, n, salt));
            return h;
        }

        public byte[] Digest(byte[] password, byte[] mod, byte[] salt)
        {
            int k = mod.Length;
            if (k < 160)
            {
                //raise error: Modulus must be greater than 160 bytes
                throw new ArgumentOutOfRangeException("Modulus must be greater than 160 bytes");
            }
            if (prehashing)
            {
                password = KDF(password, 64);
            }
            int u = password.Length;
            if (u > 255 || u > (k - 32))
            {
                // raise error: Password is too long to be hashed with these parameters
                throw new ArgumentOutOfRangeException("Password is too long to be hashed with these parameters");
            }
            byte[] ub = new byte[] { (byte)u };
            byte[] sbinput = ConcatenateByteArrays(salt, password, ub);
            byte[] sb = KDF(sbinput, k - 2 - u);
            byte[] zerobyte = new byte[] { 0 };
            byte[] xb = ConcatenateByteArrays(zerobyte, sb, password, ub);
            string xbhex = BitConverter.ToString(xb).Replace("-", "");
            xbhex = xbhex.Substring(1);
            BigInteger x = BigInteger.Parse(xbhex, System.Globalization.NumberStyles.HexNumber);
            string modhex = "0" + BitConverter.ToString(mod).Replace("-", "");
            BigInteger n = BigInteger.Parse(modhex, System.Globalization.NumberStyles.HexNumber);
            BigInteger Y = ModularSquarings(x, workfactor, n);
            byte[] y = Y.ToByteArray();
            Array.Reverse(y, 0, y.Length);
            y = y.Skip(1).Take(y.Length).ToArray();
            
            if (posthashing >= 10)
            {
                y = KDF(y, posthashing);
            }
            else if (posthashing != 0)
            {
                throw new ArgumentOutOfRangeException("PostHashing length must be at least 10 bytes long");
            }
            return y;
        }


        //public byte[] Digest(byte[] password, BigInteger mod, byte[] salt)
        //{
        //    //BigInteger n = Helpers.SimpleB2BI(Helpers.SimpleBI2B(mod));

        //    byte[] nInput = mod.ToByteArray();
        //    Array.Reverse(nInput, 0, nInput.Length);
        //    BigInteger n = new BigInteger(CombineByteArrays(new byte[] { 0 }, nInput));
        //    string nhex = n.ToString("X"); 
        //    int k = n.ToByteArray().Length;
        //    if (k < 160)
        //    {
        //        //raise error: Modulus must be greater than 160 bytes
        //        throw new ArgumentOutOfRangeException("Modulus must be greater than 160 bytes");
        //    }
        //    if (prehashing)
        //    {
        //        password = KDF(password, 64);
        //    }
        //    int u = password.Length;
        //    if (u > 255 || u > (k - 32))
        //    {
        //        // raise error: Password is too long to be hashed with these parameters
        //        throw new ArgumentOutOfRangeException("Password is too long to be hashed with these parameters");
        //    }

        //    //byte[] byteu = BitConverter.GetBytes(u);
        //    byte[] byteu = Helpers.int_to_bytes((ulong)u, 1);
        //    byte[] ubytes = BitConverter.GetBytes(u);

        //    byte[] sbinput = CombineByteArrays(salt, password, byteu);
        //    byte[] sb = KDF(sbinput, k - 2 - u);

        //    byte[] initialzero = new byte[] { 0 };
        //    byte[] xb = initialzero.Concat(sb).Concat(password).Concat(byteu).ToArray();
        //    string xbhex = BitConverter.ToString(xb).Replace("-", "");
        //    //Array.Reverse(xb, 0, xb.Length);

        //    BigInteger x = new BigInteger(Helpers.I2OSP(xb, xb.Length));
        //    string xstring = "0" + x.ToString("X");
        //    BigInteger x2 = BigInteger.Parse("0" + xbhex, System.Globalization.NumberStyles.HexNumber);
        //    string xhexpre = x.ToString("X");
        //    string xhexpre2 = x2.ToString("X");

        //    BigInteger y = new BigInteger(xb);

        //    BigInteger n2 = new BigInteger(CombineByteArrays(initialzero, Helpers.OS2IP(n.ToByteArray())));

        //    //BigInteger x2 = reversebigint(x);
        //    BigInteger n3 = reversebigint(n2);

        //    BigInteger xModPow = ModPow2(x, workfactor, n3);



        //    string xhex = xModPow.ToString("X");
        //    //int moduluslength = xb.Length;
        //    byte[] ModPowBytes = xModPow.ToByteArray().Skip(1).ToArray();
        //    byte[] output = Helpers.I2OSP(ModPowBytes, k);

        //    if (posthashing > 0)
        //    {
        //        output = KDF(output, posthashing);
        //    }
            
        //    return output;
        //}
        
        //static BigInteger reversebigint(BigInteger bint)
        //{
        //    byte[] bufferarray = bint.ToByteArray();
        //    Array.Reverse(bufferarray, 0, bufferarray.Length);
        //    return new BigInteger(bufferarray);
        //}


        //static BigInteger ModPow(BigInteger v, int wf, BigInteger mod)
        //{
        //    int step = v.ToByteArray().Length * 8;
        //    while(wf > 0)
        //    {
        //        int z = Math.Min(wf, step);
        //        v = BigInteger.ModPow(v, v << z, mod);
        //        string vhex = v.ToString("X");
        //        wf -= z;
        //    }
        //    return v;
        //}

        static BigInteger ModularSquarings(BigInteger v, int wf, BigInteger mod)
        {
            for (int i = 0; i <= wf; i++)
            {
                v = BigInteger.ModPow(v, 2, mod);
            }
            return v;
        }

        public string GetStateData()
        {
            string output = "";
            bool pre = prehashing;
            bool post = Convert.ToBoolean(posthashing);
            // TODO: Convert bools to 2 bit binary and use switch case
            if (!pre && !post) { output += "n"; }
            else
            {
                if (pre && !post) { output += "r"; }
                else
                {
                    if (!pre && post) { output += "s"; }
                    else { output += "b"; }
                }
            }
            int delta = 0;
            int w = workfactor;
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

        public byte[] KDF(byte[] data, int out_len)
        {
            byte[] hexzero = new byte[] { 0x00 };
            byte[] hexone = new byte[] { 0x01 };
            int r = hashfunction.HashSize /8;
            byte[] V = InitialiseCustomByteArray(0x01, r);
            byte[] K = InitialiseCustomByteArray(0x00, r);

            // HMAC
            HMAC hashbuffer = hashfunction;
            hashbuffer.Key = K;
            byte[] hmacdata = ConcatenateByteArrays(V, hexzero, data);
            K = hashbuffer.ComputeHash(hmacdata);
            hashbuffer.Key = K;
            V = hashbuffer.ComputeHash(V);
            K = hashbuffer.ComputeHash(ConcatenateByteArrays(V, hexone, data));
            hashbuffer.Key = K;
            V = hashbuffer.ComputeHash(V);



            IList<byte> T = new List<byte>();
            while (T.Count < out_len)
            {
                V = hashbuffer.ComputeHash(V);
                byte[] TBuffer = ConcatenateByteArrays(T.ToArray(), V);

                T = TBuffer.ToList();
            }
            var TOut = T.Take(out_len);
            byte[] output = TOut.ToArray();

            return output;
        }

        static byte[] InitialiseCustomByteArray(byte specialbytes, int length)
        {
            var arr = new byte[length];
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = specialbytes;
            }
            return arr;
        }

        public static byte[] ConcatenateByteArrays(params byte[][] arrays)
        {
            byte[] output = new byte[arrays.Sum(x => x.Length)];
            int offset = 0;
            foreach (byte[] data in arrays)
            {
                Buffer.BlockCopy(data, 0, output, offset, data.Length);
                offset += data.Length;
            }
            return output;
        }
    }

    public class Tests
    {
        public void GetRegex()
        {
            string[] lines = System.IO.File.ReadAllLines(@"kat.txt");
            //Console.WriteLine(lines.Take(1));

        }
    }
}

