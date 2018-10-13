using System;
using Makwa.BigInt;

namespace Makwa
{
    public class Tools
    {
        /// <summary>
        ///  Integer to Octet Stream Primitive, represents a Big Integer as a byte array
        /// </summary>
        public static byte[] I2OSP(BigInteger x)
        {
            return I2OSP(x, x);
        }

        /// <summary>
        ///  Integer to Octet Stream Primitive, represents a Big Integer as a 
        ///  byte array of length modulus
        /// </summary>
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

        /// <summary>
        /// Octet Stream to Integer Primitive, converts a byte array to BigInt
        /// </summary>
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

        /// <summary>
        /// Decodes a byte array into an unpadded Base64 string
        /// </summary>
        public static string DecodeBase64(byte[] m)
        {
            return Convert.ToBase64String(m).Replace("=", "");
        }

        /// <summary>
        /// Encodes an unpadded Base64 string
        /// </summary>
        public static byte[] EncodeBase64(string m)
        {
            //int len = ((4 - (m.Length % 4) % 4));
            int len = (m.Length % 4);
            string padding = new string('=', len);
            return Convert.FromBase64String(m + padding);
        }

        /// <summary>
        /// Transforms hex strings into a byte array 
        /// </summary>
        public static byte[] HexStringToByteArray(String hexstring)
        {
            int NumberChars = hexstring.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hexstring.Substring(i, 2), 16);
            return bytes;
        }

        /// <summary>
        /// Performs a byte by byte xor comparison of two arrays for the purpose 
        /// of password verification, checks every byte regardless of failure,
        /// used to prevent timing attacks.
        public static bool ConstantTimeComparison(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (uint i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        /// <summary>
        /// This implementation enforces specific work factors of the form w = ζ · 2ᵟ
        /// , where ζ = 2 or 3, and δ ≥ 0    
        /// </summary>
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

        /// <summary>
        /// Provides the closest workfactor, when an invalid workfactor is supplied
        /// </summary>
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
}
