using System;
using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using static Makwa.BigInt.DigestRandomGenerator;

namespace Makwa.BigInt
{

    public class BigInteger
    {
        // The first few odd primes
        /*
                3   5   7   11  13  17  19  23  29
            31  37  41  43  47  53  59  61  67  71
            73  79  83  89  97  101 103 107 109 113
            127 131 137 139 149 151 157 163 167 173
            179 181 191 193 197 199 211 223 227 229
            233 239 241 251 257 263 269 271 277 281
            283 293 307 311 313 317 331 337 347 349
            353 359 367 373 379 383 389 397 401 409
            419 421 431 433 439 443 449 457 461 463
            467 479 487 491 499 503 509 521 523 541
            547 557 563 569 571 577 587 593 599 601
            607 613 617 619 631 641 643 647 653 659
            661 673 677 683 691 701 709 719 727 733
            739 743 751 757 761 769 773 787 797 809
            811 821 823 827 829 839 853 857 859 863
            877 881 883 887 907 911 919 929 937 941
            947 953 967 971 977 983 991 997 1009
            1013 1019 1021 1031 1033 1039 1049 1051
            1061 1063 1069 1087 1091 1093 1097 1103
            1109 1117 1123 1129 1151 1153 1163 1171
            1181 1187 1193 1201 1213 1217 1223 1229
            1231 1237 1249 1259 1277 1279 1283 1289
        */

        // Each list has a product < 2^31
        internal static readonly int[][] primeLists = new int[][]
        {
            new int[]{ 3, 5, 7, 11, 13, 17, 19, 23 },
            new int[]{ 29, 31, 37, 41, 43 },
            new int[]{ 47, 53, 59, 61, 67 },
            new int[]{ 71, 73, 79, 83 },
            new int[]{ 89, 97, 101, 103 },

            new int[]{ 107, 109, 113, 127 },
            new int[]{ 131, 137, 139, 149 },
            new int[]{ 151, 157, 163, 167 },
            new int[]{ 173, 179, 181, 191 },
            new int[]{ 193, 197, 199, 211 },

            new int[]{ 223, 227, 229 },
            new int[]{ 233, 239, 241 },
            new int[]{ 251, 257, 263 },
            new int[]{ 269, 271, 277 },
            new int[]{ 281, 283, 293 },

            new int[]{ 307, 311, 313 },
            new int[]{ 317, 331, 337 },
            new int[]{ 347, 349, 353 },
            new int[]{ 359, 367, 373 },
            new int[]{ 379, 383, 389 },

            new int[]{ 397, 401, 409 },
            new int[]{ 419, 421, 431 },
            new int[]{ 433, 439, 443 },
            new int[]{ 449, 457, 461 },
            new int[]{ 463, 467, 479 },

            new int[]{ 487, 491, 499 },
            new int[]{ 503, 509, 521 },
            new int[]{ 523, 541, 547 },
            new int[]{ 557, 563, 569 },
            new int[]{ 571, 577, 587 },

            new int[]{ 593, 599, 601 },
            new int[]{ 607, 613, 617 },
            new int[]{ 619, 631, 641 },
            new int[]{ 643, 647, 653 },
            new int[]{ 659, 661, 673 },

            new int[]{ 677, 683, 691 },
            new int[]{ 701, 709, 719 },
            new int[]{ 727, 733, 739 },
            new int[]{ 743, 751, 757 },
            new int[]{ 761, 769, 773 },

            new int[]{ 787, 797, 809 },
            new int[]{ 811, 821, 823 },
            new int[]{ 827, 829, 839 },
            new int[]{ 853, 857, 859 },
            new int[]{ 863, 877, 881 },

            new int[]{ 883, 887, 907 },
            new int[]{ 911, 919, 929 },
            new int[]{ 937, 941, 947 },
            new int[]{ 953, 967, 971 },
            new int[]{ 977, 983, 991 },

            new int[]{ 997, 1009, 1013 },
            new int[]{ 1019, 1021, 1031 },
            new int[]{ 1033, 1039, 1049 },
            new int[]{ 1051, 1061, 1063 },
            new int[]{ 1069, 1087, 1091 },

            new int[]{ 1093, 1097, 1103 },
            new int[]{ 1109, 1117, 1123 },
            new int[]{ 1129, 1151, 1153 },
            new int[]{ 1163, 1171, 1181 },
            new int[]{ 1187, 1193, 1201 },

            new int[]{ 1213, 1217, 1223 },
            new int[]{ 1229, 1231, 1237 },
            new int[]{ 1249, 1259, 1277 },
            new int[]{ 1279, 1283, 1289 },
        };

        internal static readonly int[] primeProducts;

        private const long IMASK = 0xFFFFFFFFL;
        private const ulong UIMASK = 0xFFFFFFFFUL;

        private static readonly int[] ZeroMagnitude = new int[0];
        private static readonly byte[] ZeroEncoding = new byte[0];

        private static readonly BigInteger[] SMALL_CONSTANTS = new BigInteger[17];
        public static readonly BigInteger Zero;
        public static readonly BigInteger One;
        public static readonly BigInteger Two;
        public static readonly BigInteger Three;
        public static readonly BigInteger Ten;

        //private readonly static byte[] BitCountTable =
        //{
        //    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        //    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        //    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        //    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        //    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        //    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        //    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        //    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        //    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        //    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        //    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        //    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        //    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        //    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        //    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        //    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
        //};

        private readonly static byte[] BitLengthTable =
        {
            0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
            6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
            6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
        };

        // TODO Parse radix-2 64 bits at a time and radix-8 63 bits at a time
        private const int chunk2 = 1, chunk8 = 1, chunk10 = 19, chunk16 = 16;
        private static readonly BigInteger radix2, radix2E, radix8, radix8E, radix10, radix10E, radix16, radix16E;

        private static readonly SecureRandom RandomSource = new SecureRandom();

        /*
         * These are the threshold bit-lengths (of an exponent) where we increase the window size.
         * They are calculated according to the expected savings in multiplications.
         * Some squares will also be saved on average, but we offset these against the extra storage costs.
         */
        private static readonly int[] ExpWindowThresholds = { 7, 25, 81, 241, 673, 1793, 4609, Int32.MaxValue };

        private const int BitsPerByte = 8;
        private const int BitsPerInt = 32;
        private const int BytesPerInt = 4;

        static BigInteger()
        {
            Zero = new BigInteger(0, ZeroMagnitude, false);
            Zero.nBits = 0; Zero.nBitLength = 0;

            SMALL_CONSTANTS[0] = Zero;
            for (uint i = 1; i < SMALL_CONSTANTS.Length; ++i)
            {
                SMALL_CONSTANTS[i] = CreateUValueOf(i);
            }

            One = SMALL_CONSTANTS[1];
            Two = SMALL_CONSTANTS[2];
            Three = SMALL_CONSTANTS[3];
            Ten = SMALL_CONSTANTS[10];

            radix2 = ValueOf(2);
            radix2E = radix2.Pow(chunk2);

            radix8 = ValueOf(8);
            radix8E = radix8.Pow(chunk8);

            radix10 = ValueOf(10);
            radix10E = radix10.Pow(chunk10);

            radix16 = ValueOf(16);
            radix16E = radix16.Pow(chunk16);

            primeProducts = new int[primeLists.Length];

            for (int i = 0; i < primeLists.Length; ++i)
            {
                int[] primeList = primeLists[i];
                int product = primeList[0];
                for (int j = 1; j < primeList.Length; ++j)
                {
                    product *= primeList[j];
                }
                primeProducts[i] = product;
            }
        }

        private int[] magnitude; // array of ints with [0] being the most significant
        private int sign; // -1 means -ve; +1 means +ve; 0 means 0;
        private int nBits = -1; // cache BitCount() value
        private int nBitLength = -1; // cache BitLength() value
        private int mQuote = 0; // -m^(-1) mod b, b = 2^32 (see Montgomery mult.), 0 when uninitialised

        private static int GetByteLength(
            int nBits)
        {
            return (nBits + BitsPerByte - 1) / BitsPerByte;
        }

        internal static BigInteger Arbitrary(int sizeInBits)
        {
            return new BigInteger(sizeInBits, RandomSource);
        }

        private BigInteger(
            int signum,
            int[] mag,
            bool checkMag)
        {
            if (checkMag)
            {
                int i = 0;
                while (i < mag.Length && mag[i] == 0)
                {
                    ++i;
                }

                if (i == mag.Length)
                {
                    this.sign = 0;
                    this.magnitude = ZeroMagnitude;
                }
                else
                {
                    this.sign = signum;

                    if (i == 0)
                    {
                        this.magnitude = mag;
                    }
                    else
                    {
                        // strip leading 0 words
                        this.magnitude = new int[mag.Length - i];
                        Array.Copy(mag, i, this.magnitude, 0, this.magnitude.Length);
                    }
                }
            }
            else
            {
                this.sign = signum;
                this.magnitude = mag;
            }
        }

        public BigInteger(
            string value)
            : this(value, 10)
        {
        }

        public BigInteger(
            string str,
            int radix)
        {
            if (str.Length == 0)
                throw new FormatException("Zero length BigInteger");

            NumberStyles style;
            int chunk;
            BigInteger r;
            BigInteger rE;

            switch (radix)
            {
                case 2:
                    // Is there anyway to restrict to binary digits?
                    style = NumberStyles.Integer;
                    chunk = chunk2;
                    r = radix2;
                    rE = radix2E;
                    break;
                case 8:
                    // Is there anyway to restrict to octal digits?
                    style = NumberStyles.Integer;
                    chunk = chunk8;
                    r = radix8;
                    rE = radix8E;
                    break;
                case 10:
                    // This style seems to handle spaces and minus sign already (our processing redundant?)
                    style = NumberStyles.Integer;
                    chunk = chunk10;
                    r = radix10;
                    rE = radix10E;
                    break;
                case 16:
                    // TODO Should this be HexNumber?
                    style = NumberStyles.AllowHexSpecifier;
                    chunk = chunk16;
                    r = radix16;
                    rE = radix16E;
                    break;
                default:
                    throw new FormatException("Only bases 2, 8, 10, or 16 allowed");
            }


            int index = 0;
            sign = 1;

            if (str[0] == '-')
            {
                if (str.Length == 1)
                    throw new FormatException("Zero length BigInteger");

                sign = -1;
                index = 1;
            }

            // strip leading zeros from the string str
            while (index < str.Length && Int32.Parse(str[index].ToString(), style) == 0)
            {
                index++;
            }

            if (index >= str.Length)
            {
                // zero value - we're done
                sign = 0;
                magnitude = ZeroMagnitude;
                return;
            }

            //////
            // could we work out the max number of ints required to store
            // str.Length digits in the given base, then allocate that
            // storage in one hit?, then Generate the magnitude in one hit too?
            //////

            BigInteger b = Zero;


            int next = index + chunk;

            if (next <= str.Length)
            {
                do
                {
                    string s = str.Substring(index, chunk);
                    ulong i = ulong.Parse(s, style);
                    BigInteger bi = CreateUValueOf(i);

                    switch (radix)
                    {
                        case 2:
                            // TODO Need this because we are parsing in radix 10 above
                            if (i >= 2)
                                throw new FormatException("Bad character in radix 2 string: " + s);

                            // TODO Parse 64 bits at a time
                            b = b.ShiftLeft(1);
                            break;
                        case 8:
                            // TODO Need this because we are parsing in radix 10 above
                            if (i >= 8)
                                throw new FormatException("Bad character in radix 8 string: " + s);

                            // TODO Parse 63 bits at a time
                            b = b.ShiftLeft(3);
                            break;
                        case 16:
                            b = b.ShiftLeft(64);
                            break;
                        default:
                            b = b.Multiply(rE);
                            break;
                    }

                    b = b.Add(bi);

                    index = next;
                    next += chunk;
                }
                while (next <= str.Length);
            }

            if (index < str.Length)
            {
                string s = str.Substring(index);
                ulong i = ulong.Parse(s, style);
                BigInteger bi = CreateUValueOf(i);

                if (b.sign > 0)
                {
                    if (radix == 2)
                    {
                        // NB: Can't reach here since we are parsing one char at a time
                        Debug.Assert(false);

                        // TODO Parse all bits at once
                        //						b = b.ShiftLeft(s.Length);
                    }
                    else if (radix == 8)
                    {
                        // NB: Can't reach here since we are parsing one char at a time
                        Debug.Assert(false);

                        // TODO Parse all bits at once
                        //						b = b.ShiftLeft(s.Length * 3);
                    }
                    else if (radix == 16)
                    {
                        b = b.ShiftLeft(s.Length << 2);
                    }
                    else
                    {
                        b = b.Multiply(r.Pow(s.Length));
                    }

                    b = b.Add(bi);
                }
                else
                {
                    b = bi;
                }
            }

            // Note: This is the previous (slower) algorithm
            //			while (index < value.Length)
            //            {
            //				char c = value[index];
            //				string s = c.ToString();
            //				int i = Int32.Parse(s, style);
            //
            //                b = b.Multiply(r).Add(ValueOf(i));
            //                index++;
            //            }

            magnitude = b.magnitude;
        }

        public BigInteger(
            byte[] bytes)
            : this(bytes, 0, bytes.Length)
        {
        }

        public BigInteger(
            byte[] bytes,
            int offset,
            int length)
        {
            if (length == 0)
                throw new FormatException("Zero length BigInteger");

            // TODO Move this processing into MakeMagnitude (provide sign argument)
            if ((sbyte)bytes[offset] < 0)
            {
                this.sign = -1;

                int end = offset + length;

                int iBval;
                // strip leading sign bytes
                for (iBval = offset; iBval < end && ((sbyte)bytes[iBval] == -1); iBval++)
                {
                }

                if (iBval >= end)
                {
                    this.magnitude = One.magnitude;
                }
                else
                {
                    int numBytes = end - iBval;
                    byte[] inverse = new byte[numBytes];

                    int index = 0;
                    while (index < numBytes)
                    {
                        inverse[index++] = (byte)~bytes[iBval++];
                    }

                    Debug.Assert(iBval == end);

                    while (inverse[--index] == byte.MaxValue)
                    {
                        inverse[index] = byte.MinValue;
                    }

                    inverse[index]++;

                    this.magnitude = MakeMagnitude(inverse, 0, inverse.Length);
                }
            }
            else
            {
                // strip leading zero bytes and return magnitude bytes
                this.magnitude = MakeMagnitude(bytes, offset, length);
                this.sign = this.magnitude.Length > 0 ? 1 : 0;
            }
        }

        private static int[] MakeMagnitude(
            byte[] bytes,
            int offset,
            int length)
        {
            int end = offset + length;

            // strip leading zeros
            int firstSignificant;
            for (firstSignificant = offset; firstSignificant < end
                && bytes[firstSignificant] == 0; firstSignificant++)
            {
            }

            if (firstSignificant >= end)
            {
                return ZeroMagnitude;
            }

            int nInts = (end - firstSignificant + 3) / BytesPerInt;
            int bCount = (end - firstSignificant) % BytesPerInt;
            if (bCount == 0)
            {
                bCount = BytesPerInt;
            }

            if (nInts < 1)
            {
                return ZeroMagnitude;
            }

            int[] mag = new int[nInts];

            int v = 0;
            int magnitudeIndex = 0;
            for (int i = firstSignificant; i < end; ++i)
            {
                v <<= 8;
                v |= bytes[i] & 0xff;
                bCount--;
                if (bCount <= 0)
                {
                    mag[magnitudeIndex] = v;
                    magnitudeIndex++;
                    bCount = BytesPerInt;
                    v = 0;
                }
            }

            if (magnitudeIndex < mag.Length)
            {
                mag[magnitudeIndex] = v;
            }

            return mag;
        }

        public BigInteger(
            int sign,
            byte[] bytes)
            : this(sign, bytes, 0, bytes.Length)
        {
        }

        public BigInteger(
            int sign,
            byte[] bytes,
            int offset,
            int length)
        {
            if (sign < -1 || sign > 1)
                throw new FormatException("Invalid sign value");

            if (sign == 0)
            {
                this.sign = 0;
                this.magnitude = ZeroMagnitude;
            }
            else
            {
                // copy bytes
                this.magnitude = MakeMagnitude(bytes, offset, length);
                this.sign = this.magnitude.Length < 1 ? 0 : sign;
            }
        }

        public BigInteger(
            int sizeInBits,
            Random random)
        {
            if (sizeInBits < 0)
                throw new ArgumentException("sizeInBits must be non-negative");

            this.nBits = -1;
            this.nBitLength = -1;

            if (sizeInBits == 0)
            {
                this.sign = 0;
                this.magnitude = ZeroMagnitude;
                return;
            }

            int nBytes = GetByteLength(sizeInBits);
            byte[] b = new byte[nBytes];
            random.NextBytes(b);

            // strip off any excess bits in the MSB
            int xBits = BitsPerByte * nBytes - sizeInBits;
            b[0] &= (byte)(255U >> xBits);

            this.magnitude = MakeMagnitude(b, 0, b.Length);
            this.sign = this.magnitude.Length < 1 ? 0 : 1;
        }

        public BigInteger(
            int bitLength,
            int certainty,
            Random random)
        {
            if (bitLength < 2)
                throw new ArithmeticException("bitLength < 2");

            this.sign = 1;
            this.nBitLength = bitLength;

            if (bitLength == 2)
            {
                this.magnitude = random.Next(2) == 0
                    ? Two.magnitude
                    : Three.magnitude;
                return;
            }

            int nBytes = GetByteLength(bitLength);
            byte[] b = new byte[nBytes];

            int xBits = BitsPerByte * nBytes - bitLength;
            byte mask = (byte)(255U >> xBits);
            byte lead = (byte)(1 << (7 - xBits));

            for (; ; )
            {
                random.NextBytes(b);

                // strip off any excess bits in the MSB
                b[0] &= mask;

                // ensure the leading bit is 1 (to meet the strength requirement)
                b[0] |= lead;

                // ensure the trailing bit is 1 (i.e. must be odd)
                b[nBytes - 1] |= 1;

                this.magnitude = MakeMagnitude(b, 0, b.Length);
                this.nBits = -1;
                this.mQuote = 0;

                if (certainty < 1)
                    break;

                if (CheckProbablePrime(certainty, random, true))
                    break;

                for (int j = 1; j < (magnitude.Length - 1); ++j)
                {
                    this.magnitude[j] ^= random.Next();

                    if (CheckProbablePrime(certainty, random, true))
                        return;
                }
            }
        }

        public BigInteger Abs()
        {
            return sign >= 0 ? this : Negate();
        }

        /**
         * return a = a + b - b preserved.
         */
        private static int[] AddMagnitudes(
            int[] a,
            int[] b)
        {
            int tI = a.Length - 1;
            int vI = b.Length - 1;
            long m = 0;

            while (vI >= 0)
            {
                m += ((long)(uint)a[tI] + (long)(uint)b[vI--]);
                a[tI--] = (int)m;
                m = (long)((ulong)m >> 32);
            }

            if (m != 0)
            {
                while (tI >= 0 && ++a[tI--] == 0)
                {
                }
            }

            return a;
        }

        public BigInteger Add(
            BigInteger value)
        {
            if (this.sign == 0)
                return value;

            if (this.sign != value.sign)
            {
                if (value.sign == 0)
                    return this;

                if (value.sign < 0)
                    return Subtract(value.Negate());

                return value.Subtract(Negate());
            }

            return AddToMagnitude(value.magnitude);
        }

        private BigInteger AddToMagnitude(
            int[] magToAdd)
        {
            int[] big, small;
            if (this.magnitude.Length < magToAdd.Length)
            {
                big = magToAdd;
                small = this.magnitude;
            }
            else
            {
                big = this.magnitude;
                small = magToAdd;
            }

            // Conservatively avoid over-allocation when no overflow possible
            uint limit = uint.MaxValue;
            if (big.Length == small.Length)
                limit -= (uint)small[0];

            bool possibleOverflow = (uint)big[0] >= limit;

            int[] bigCopy;
            if (possibleOverflow)
            {
                bigCopy = new int[big.Length + 1];
                big.CopyTo(bigCopy, 1);
            }
            else
            {
                bigCopy = (int[])big.Clone();
            }

            bigCopy = AddMagnitudes(bigCopy, small);

            return new BigInteger(this.sign, bigCopy, possibleOverflow);
        }

        public BigInteger And(
            BigInteger value)
        {
            if (this.sign == 0 || value.sign == 0)
            {
                return Zero;
            }

            int[] aMag = this.sign > 0
                ? this.magnitude
                : Add(One).magnitude;

            int[] bMag = value.sign > 0
                ? value.magnitude
                : value.Add(One).magnitude;

            bool resultNeg = sign < 0 && value.sign < 0;
            int resultLength = System.Math.Max(aMag.Length, bMag.Length);
            int[] resultMag = new int[resultLength];

            int aStart = resultMag.Length - aMag.Length;
            int bStart = resultMag.Length - bMag.Length;

            for (int i = 0; i < resultMag.Length; ++i)
            {
                int aWord = i >= aStart ? aMag[i - aStart] : 0;
                int bWord = i >= bStart ? bMag[i - bStart] : 0;

                if (this.sign < 0)
                {
                    aWord = ~aWord;
                }

                if (value.sign < 0)
                {
                    bWord = ~bWord;
                }

                resultMag[i] = aWord & bWord;

                if (resultNeg)
                {
                    resultMag[i] = ~resultMag[i];
                }
            }

            BigInteger result = new BigInteger(1, resultMag, true);

            // TODO Optimise this case
            if (resultNeg)
            {
                result = result.Not();
            }

            return result;
        }

        public BigInteger AndNot(
            BigInteger val)
        {
            return And(val.Not());
        }

        public int BitCount
        {
            get
            {
                if (nBits == -1)
                {
                    if (sign < 0)
                    {
                        // TODO Optimise this case
                        nBits = Not().BitCount;
                    }
                    else
                    {
                        int sum = 0;
                        for (int i = 0; i < magnitude.Length; ++i)
                        {
                            sum += BitCnt(magnitude[i]);
                        }
                        nBits = sum;
                    }
                }

                return nBits;
            }
        }

        public static int BitCnt(int i)
        {
            uint u = (uint)i;
            u = u - ((u >> 1) & 0x55555555);
            u = (u & 0x33333333) + ((u >> 2) & 0x33333333);
            u = (u + (u >> 4)) & 0x0f0f0f0f;
            u += (u >> 8);
            u += (u >> 16);
            u &= 0x3f;
            return (int)u;
        }

        private static int CalcBitLength(int sign, int indx, int[] mag)
        {
            for (; ; )
            {
                if (indx >= mag.Length)
                    return 0;

                if (mag[indx] != 0)
                    break;

                ++indx;
            }

            // bit length for everything after the first int
            int bitLength = 32 * ((mag.Length - indx) - 1);

            // and determine bitlength of first int
            int firstMag = mag[indx];
            bitLength += BitLen(firstMag);

            // Check for negative powers of two
            if (sign < 0 && ((firstMag & -firstMag) == firstMag))
            {
                do
                {
                    if (++indx >= mag.Length)
                    {
                        --bitLength;
                        break;
                    }
                }
                while (mag[indx] == 0);
            }

            return bitLength;
        }

        public int BitLength
        {
            get
            {
                if (nBitLength == -1)
                {
                    nBitLength = sign == 0
                        ? 0
                        : CalcBitLength(sign, 0, magnitude);
                }

                return nBitLength;
            }
        }

        //
        // BitLen(value) is the number of bits in value.
        //
        internal static int BitLen(int w)
        {
            uint v = (uint)w;
            uint t = v >> 24;
            if (t != 0)
                return 24 + BitLengthTable[t];
            t = v >> 16;
            if (t != 0)
                return 16 + BitLengthTable[t];
            t = v >> 8;
            if (t != 0)
                return 8 + BitLengthTable[t];
            return BitLengthTable[v];
        }

        private bool QuickPow2Check()
        {
            return sign > 0 && nBits == 1;
        }

        public int CompareTo(
            object obj)
        {
            return CompareTo((BigInteger)obj);
        }

        /**
         * unsigned comparison on two arrays - note the arrays may
         * start with leading zeros.
         */
        private static int CompareTo(
            int xIndx,
            int[] x,
            int yIndx,
            int[] y)
        {
            while (xIndx != x.Length && x[xIndx] == 0)
            {
                xIndx++;
            }

            while (yIndx != y.Length && y[yIndx] == 0)
            {
                yIndx++;
            }

            return CompareNoLeadingZeroes(xIndx, x, yIndx, y);
        }

        private static int CompareNoLeadingZeroes(
            int xIndx,
            int[] x,
            int yIndx,
            int[] y)
        {
            int diff = (x.Length - y.Length) - (xIndx - yIndx);

            if (diff != 0)
            {
                return diff < 0 ? -1 : 1;
            }

            // lengths of magnitudes the same, test the magnitude values

            while (xIndx < x.Length)
            {
                uint v1 = (uint)x[xIndx++];
                uint v2 = (uint)y[yIndx++];

                if (v1 != v2)
                    return v1 < v2 ? -1 : 1;
            }

            return 0;
        }

        public int CompareTo(
            BigInteger value)
        {
            return sign < value.sign ? -1
                : sign > value.sign ? 1
                : sign == 0 ? 0
                : sign * CompareNoLeadingZeroes(0, magnitude, 0, value.magnitude);
        }

        /**
         * return z = x / y - done in place (z value preserved, x contains the
         * remainder)
         */
        private int[] Divide(
            int[] x,
            int[] y)
        {
            int xStart = 0;
            while (xStart < x.Length && x[xStart] == 0)
            {
                ++xStart;
            }

            int yStart = 0;
            while (yStart < y.Length && y[yStart] == 0)
            {
                ++yStart;
            }

            Debug.Assert(yStart < y.Length);

            int xyCmp = CompareNoLeadingZeroes(xStart, x, yStart, y);
            int[] count;

            if (xyCmp > 0)
            {
                int yBitLength = CalcBitLength(1, yStart, y);
                int xBitLength = CalcBitLength(1, xStart, x);
                int shift = xBitLength - yBitLength;

                int[] iCount;
                int iCountStart = 0;

                int[] c;
                int cStart = 0;
                int cBitLength = yBitLength;
                if (shift > 0)
                {
                    //					iCount = ShiftLeft(One.magnitude, shift);
                    iCount = new int[(shift >> 5) + 1];
                    iCount[0] = 1 << (shift % 32);

                    c = ShiftLeft(y, shift);
                    cBitLength += shift;
                }
                else
                {
                    iCount = new int[] { 1 };

                    int len = y.Length - yStart;
                    c = new int[len];
                    Array.Copy(y, yStart, c, 0, len);
                }

                count = new int[iCount.Length];

                for (; ; )
                {
                    if (cBitLength < xBitLength
                        || CompareNoLeadingZeroes(xStart, x, cStart, c) >= 0)
                    {
                        Subtract(xStart, x, cStart, c);
                        AddMagnitudes(count, iCount);

                        while (x[xStart] == 0)
                        {
                            if (++xStart == x.Length)
                                return count;
                        }

                        //xBitLength = CalcBitLength(xStart, x);
                        xBitLength = 32 * (x.Length - xStart - 1) + BitLen(x[xStart]);

                        if (xBitLength <= yBitLength)
                        {
                            if (xBitLength < yBitLength)
                                return count;

                            xyCmp = CompareNoLeadingZeroes(xStart, x, yStart, y);

                            if (xyCmp <= 0)
                                break;
                        }
                    }

                    shift = cBitLength - xBitLength;

                    // NB: The case where c[cStart] is 1-bit is harmless
                    if (shift == 1)
                    {
                        uint firstC = (uint)c[cStart] >> 1;
                        uint firstX = (uint)x[xStart];
                        if (firstC > firstX)
                            ++shift;
                    }

                    if (shift < 2)
                    {
                        ShiftRightOneInPlace(cStart, c);
                        --cBitLength;
                        ShiftRightOneInPlace(iCountStart, iCount);
                    }
                    else
                    {
                        ShiftRightInPlace(cStart, c, shift);
                        cBitLength -= shift;
                        ShiftRightInPlace(iCountStart, iCount, shift);
                    }

                    //cStart = c.Length - ((cBitLength + 31) / 32);
                    while (c[cStart] == 0)
                    {
                        ++cStart;
                    }

                    while (iCount[iCountStart] == 0)
                    {
                        ++iCountStart;
                    }
                }
            }
            else
            {
                count = new int[1];
            }

            if (xyCmp == 0)
            {
                AddMagnitudes(count, One.magnitude);
                Array.Clear(x, xStart, x.Length - xStart);
            }

            return count;
        }

        public BigInteger Divide(
            BigInteger val)
        {
            if (val.sign == 0)
                throw new ArithmeticException("Division by zero error");

            if (sign == 0)
                return Zero;

            if (val.QuickPow2Check()) // val is power of two
            {
                BigInteger result = this.Abs().ShiftRight(val.Abs().BitLength - 1);
                return val.sign == this.sign ? result : result.Negate();
            }

            int[] mag = (int[])this.magnitude.Clone();

            return new BigInteger(this.sign * val.sign, Divide(mag, val.magnitude), true);
        }

        public BigInteger[] DivideAndRemainder(
            BigInteger val)
        {
            if (val.sign == 0)
                throw new ArithmeticException("Division by zero error");

            BigInteger[] biggies = new BigInteger[2];

            if (sign == 0)
            {
                biggies[0] = Zero;
                biggies[1] = Zero;
            }
            else if (val.QuickPow2Check()) // val is power of two
            {
                int e = val.Abs().BitLength - 1;
                BigInteger quotient = this.Abs().ShiftRight(e);
                int[] remainder = this.LastNBits(e);

                biggies[0] = val.sign == this.sign ? quotient : quotient.Negate();
                biggies[1] = new BigInteger(this.sign, remainder, true);
            }
            else
            {
                int[] remainder = (int[])this.magnitude.Clone();
                int[] quotient = Divide(remainder, val.magnitude);

                biggies[0] = new BigInteger(this.sign * val.sign, quotient, true);
                biggies[1] = new BigInteger(this.sign, remainder, true);
            }

            return biggies;
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            BigInteger biggie = obj as BigInteger;
            if (biggie == null)
                return false;

            return sign == biggie.sign && IsEqualMagnitude(biggie);
        }

        private bool IsEqualMagnitude(BigInteger x)
        {
            int[] xMag = x.magnitude;
            if (magnitude.Length != x.magnitude.Length)
                return false;
            for (int i = 0; i < magnitude.Length; i++)
            {
                if (magnitude[i] != x.magnitude[i])
                    return false;
            }
            return true;
        }

        public BigInteger Gcd(
            BigInteger value)
        {
            if (value.sign == 0)
                return Abs();

            if (sign == 0)
                return value.Abs();

            BigInteger r;
            BigInteger u = this;
            BigInteger v = value;

            while (v.sign != 0)
            {
                r = u.Mod(v);
                u = v;
                v = r;
            }

            return u;
        }

        public override int GetHashCode()
        {
            int hc = magnitude.Length;
            if (magnitude.Length > 0)
            {
                hc ^= magnitude[0];

                if (magnitude.Length > 1)
                {
                    hc ^= magnitude[magnitude.Length - 1];
                }
            }

            return sign < 0 ? ~hc : hc;
        }

        // TODO Make public?
        private BigInteger Inc()
        {
            if (this.sign == 0)
                return One;

            if (this.sign < 0)
                return new BigInteger(-1, doSubBigLil(this.magnitude, One.magnitude), true);

            return AddToMagnitude(One.magnitude);
        }

        public int IntValue
        {
            get
            {
                if (sign == 0)
                    return 0;

                int n = magnitude.Length;

                int v = magnitude[n - 1];

                return sign < 0 ? -v : v;
            }
        }

        /**
         * return whether or not a BigInteger is probably prime with a
         * probability of 1 - (1/2)**certainty.
         * <p>From Knuth Vol 2, pg 395.</p>
         */
        public bool IsProbablePrime(int certainty)
        {
            return IsProbablePrime(certainty, false);
        }

        internal bool IsProbablePrime(int certainty, bool randomlySelected)
        {
            if (certainty <= 0)
                return true;

            BigInteger n = Abs();

            if (!n.TestBit(0))
                return n.Equals(Two);

            if (n.Equals(One))
                return false;

            return n.CheckProbablePrime(certainty, RandomSource, randomlySelected);
        }

        private bool CheckProbablePrime(int certainty, Random random, bool randomlySelected)
        {
            Debug.Assert(certainty > 0);
            Debug.Assert(CompareTo(Two) > 0);
            Debug.Assert(TestBit(0));


            // Try to reduce the penalty for really small numbers
            int numLists = Math.Min(BitLength - 1, primeLists.Length);

            for (int i = 0; i < numLists; ++i)
            {
                int test = Remainder(primeProducts[i]);

                int[] primeList = primeLists[i];
                for (int j = 0; j < primeList.Length; ++j)
                {
                    int prime = primeList[j];
                    int qRem = test % prime;
                    if (qRem == 0)
                    {
                        // We may find small numbers in the list
                        return BitLength < 16 && IntValue == prime;
                    }
                }
            }


            // TODO Special case for < 10^16 (RabinMiller fixed list)
            //			if (BitLength < 30)
            //			{
            //				RabinMiller against 2, 3, 5, 7, 11, 13, 23 is sufficient
            //			}


            // TODO Is it worth trying to create a hybrid of these two?
            return RabinMillerTest(certainty, random, randomlySelected);
            //			return SolovayStrassenTest(certainty, random);

            //			bool rbTest = RabinMillerTest(certainty, random);
            //			bool ssTest = SolovayStrassenTest(certainty, random);
            //
            //			Debug.Assert(rbTest == ssTest);
            //
            //			return rbTest;
        }

        public bool RabinMillerTest(int certainty, Random random)
        {
            return RabinMillerTest(certainty, random, false);
        }

        internal bool RabinMillerTest(int certainty, Random random, bool randomlySelected)
        {
            int bits = BitLength;

            Debug.Assert(certainty > 0);
            Debug.Assert(bits > 2);
            Debug.Assert(TestBit(0));

            int iterations = ((certainty - 1) / 2) + 1;
            if (randomlySelected)
            {
                int itersFor100Cert = bits >= 1024 ? 4
                                    : bits >= 512 ? 8
                                    : bits >= 256 ? 16
                                    : 50;

                if (certainty < 100)
                {
                    iterations = Math.Min(itersFor100Cert, iterations);
                }
                else
                {
                    iterations -= 50;
                    iterations += itersFor100Cert;
                }
            }

            // let n = 1 + d . 2^s
            BigInteger n = this;
            int s = n.GetLowestSetBitMaskFirst(-1 << 1);
            Debug.Assert(s >= 1);
            BigInteger r = n.ShiftRight(s);

            // NOTE: Avoid conversion to/from Montgomery form and check for R/-R as result instead

            BigInteger montRadix = One.ShiftLeft(32 * n.magnitude.Length).Remainder(n);
            BigInteger minusMontRadix = n.Subtract(montRadix);

            do
            {
                BigInteger a;
                do
                {
                    a = new BigInteger(n.BitLength, random);
                }
                while (a.sign == 0 || a.CompareTo(n) >= 0
                    || a.IsEqualMagnitude(montRadix) || a.IsEqualMagnitude(minusMontRadix));

                BigInteger y = ModPowMonty(a, r, n, false);

                if (!y.Equals(montRadix))
                {
                    int j = 0;
                    while (!y.Equals(minusMontRadix))
                    {
                        if (++j == s)
                            return false;

                        y = ModPowMonty(y, Two, n, false);

                        if (y.Equals(montRadix))
                            return false;
                    }
                }
            }
            while (--iterations > 0);

            return true;
        }

        public long LongValue
        {
            get
            {
                if (sign == 0)
                    return 0;

                int n = magnitude.Length;

                long v = magnitude[n - 1] & IMASK;
                if (n > 1)
                {
                    v |= (magnitude[n - 2] & IMASK) << 32;
                }

                return sign < 0 ? -v : v;
            }
        }

        public BigInteger Max(
            BigInteger value)
        {
            return CompareTo(value) > 0 ? this : value;
        }

        public BigInteger Min(
            BigInteger value)
        {
            return CompareTo(value) < 0 ? this : value;
        }

        public BigInteger Mod(
            BigInteger m)
        {
            if (m.sign < 1)
                throw new ArithmeticException("Modulus must be positive");

            BigInteger biggie = Remainder(m);

            return (biggie.sign >= 0 ? biggie : biggie.Add(m));
        }

        public BigInteger ModInverse(
            BigInteger m)
        {
            if (m.sign < 1)
                throw new ArithmeticException("Modulus must be positive");

            if (m.QuickPow2Check())
            {
                return ModInversePow2(m);
            }

            BigInteger d = this.Remainder(m);
            BigInteger x;
            BigInteger gcd = ExtEuclid(d, m, out x);

            if (!gcd.Equals(One))
                throw new ArithmeticException("Numbers not relatively prime.");

            if (x.sign < 0)
            {
                x = x.Add(m);
            }

            return x;
        }

        private BigInteger ModInversePow2(BigInteger m)
        {
            Debug.Assert(m.SignValue > 0);
            Debug.Assert(m.BitCount == 1);

            if (!TestBit(0))
            {
                throw new ArithmeticException("Numbers not relatively prime.");
            }

            int pow = m.BitLength - 1;

            long inv64 = ModInverse64(LongValue);
            if (pow < 64)
            {
                inv64 &= ((1L << pow) - 1);
            }

            BigInteger x = BigInteger.ValueOf(inv64);

            if (pow > 64)
            {
                BigInteger d = this.Remainder(m);
                int bitsCorrect = 64;

                do
                {
                    BigInteger t = x.Multiply(d).Remainder(m);
                    x = x.Multiply(Two.Subtract(t)).Remainder(m);
                    bitsCorrect <<= 1;
                }
                while (bitsCorrect < pow);
            }

            if (x.sign < 0)
            {
                x = x.Add(m);
            }

            return x;
        }

        private static int ModInverse32(int d)
        {
            // Newton's method with initial estimate "correct to 4 bits"
            Debug.Assert((d & 1) != 0);
            int x = d + (((d + 1) & 4) << 1);   // d.x == 1 mod 2**4
            Debug.Assert(((d * x) & 15) == 1);
            x *= 2 - d * x;                     // d.x == 1 mod 2**8
            x *= 2 - d * x;                     // d.x == 1 mod 2**16
            x *= 2 - d * x;                     // d.x == 1 mod 2**32
            Debug.Assert(d * x == 1);
            return x;
        }

        private static long ModInverse64(long d)
        {
            // Newton's method with initial estimate "correct to 4 bits"
            Debug.Assert((d & 1L) != 0);
            long x = d + (((d + 1L) & 4L) << 1);    // d.x == 1 mod 2**4
            Debug.Assert(((d * x) & 15L) == 1L);
            x *= 2 - d * x;                         // d.x == 1 mod 2**8
            x *= 2 - d * x;                         // d.x == 1 mod 2**16
            x *= 2 - d * x;                         // d.x == 1 mod 2**32
            x *= 2 - d * x;                         // d.x == 1 mod 2**64
            Debug.Assert(d * x == 1L);
            return x;
        }

        /**
         * Calculate the numbers u1, u2, and u3 such that:
         *
         * u1 * a + u2 * b = u3
         *
         * where u3 is the greatest common divider of a and b.
         * a and b using the extended Euclid algorithm (refer p. 323
         * of The Art of Computer Programming vol 2, 2nd ed).
         * This also seems to have the side effect of calculating
         * some form of multiplicative inverse.
         *
         * @param a    First number to calculate gcd for
         * @param b    Second number to calculate gcd for
         * @param u1Out      the return object for the u1 value
         * @return     The greatest common divisor of a and b
         */
        private static BigInteger ExtEuclid(BigInteger a, BigInteger b, out BigInteger u1Out)
        {
            BigInteger u1 = One, v1 = Zero;
            BigInteger u3 = a, v3 = b;

            if (v3.sign > 0)
            {
                for (; ; )
                {
                    BigInteger[] q = u3.DivideAndRemainder(v3);
                    u3 = v3;
                    v3 = q[1];

                    BigInteger oldU1 = u1;
                    u1 = v1;

                    if (v3.sign <= 0)
                        break;

                    v1 = oldU1.Subtract(v1.Multiply(q[0]));
                }
            }

            u1Out = u1;

            return u3;
        }

        private static void ZeroOut(
            int[] x)
        {
            Array.Clear(x, 0, x.Length);
        }

        public BigInteger ModPow(BigInteger e, BigInteger m)
        {
            if (m.sign < 1)
                throw new ArithmeticException("Modulus must be positive");

            if (m.Equals(One))
                return Zero;

            if (e.sign == 0)
                return One;

            if (sign == 0)
                return Zero;

            bool negExp = e.sign < 0;
            if (negExp)
                e = e.Negate();

            BigInteger result = this.Mod(m);
            if (!e.Equals(One))
            {
                if ((m.magnitude[m.magnitude.Length - 1] & 1) == 0)
                {
                    result = ModPowBarrett(result, e, m);
                }
                else
                {
                    result = ModPowMonty(result, e, m, true);
                }
            }

            if (negExp)
                result = result.ModInverse(m);

            return result;
        }

        private static BigInteger ModPowBarrett(BigInteger b, BigInteger e, BigInteger m)
        {
            int k = m.magnitude.Length;
            BigInteger mr = One.ShiftLeft((k + 1) << 5);
            BigInteger yu = One.ShiftLeft(k << 6).Divide(m);

            // Sliding window from MSW to LSW
            int extraBits = 0, expLength = e.BitLength;
            while (expLength > ExpWindowThresholds[extraBits])
            {
                ++extraBits;
            }

            int numPowers = 1 << extraBits;
            BigInteger[] oddPowers = new BigInteger[numPowers];
            oddPowers[0] = b;

            BigInteger b2 = ReduceBarrett(b.Square(), m, mr, yu);

            for (int i = 1; i < numPowers; ++i)
            {
                oddPowers[i] = ReduceBarrett(oddPowers[i - 1].Multiply(b2), m, mr, yu);
            }

            int[] windowList = GetWindowList(e.magnitude, extraBits);
            Debug.Assert(windowList.Length > 0);

            int window = windowList[0];
            int mult = window & 0xFF, lastZeroes = window >> 8;

            BigInteger y;
            if (mult == 1)
            {
                y = b2;
                --lastZeroes;
            }
            else
            {
                y = oddPowers[mult >> 1];
            }

            int windowPos = 1;
            while ((window = windowList[windowPos++]) != -1)
            {
                mult = window & 0xFF;

                int bits = lastZeroes + BitLengthTable[mult];
                for (int j = 0; j < bits; ++j)
                {
                    y = ReduceBarrett(y.Square(), m, mr, yu);
                }

                y = ReduceBarrett(y.Multiply(oddPowers[mult >> 1]), m, mr, yu);

                lastZeroes = window >> 8;
            }

            for (int i = 0; i < lastZeroes; ++i)
            {
                y = ReduceBarrett(y.Square(), m, mr, yu);
            }

            return y;
        }

        private static BigInteger ReduceBarrett(BigInteger x, BigInteger m, BigInteger mr, BigInteger yu)
        {
            int xLen = x.BitLength, mLen = m.BitLength;
            if (xLen < mLen)
                return x;

            if (xLen - mLen > 1)
            {
                int k = m.magnitude.Length;

                BigInteger q1 = x.DivideWords(k - 1);
                BigInteger q2 = q1.Multiply(yu); // TODO Only need partial multiplication here
                BigInteger q3 = q2.DivideWords(k + 1);

                BigInteger r1 = x.RemainderWords(k + 1);
                BigInteger r2 = q3.Multiply(m); // TODO Only need partial multiplication here
                BigInteger r3 = r2.RemainderWords(k + 1);

                x = r1.Subtract(r3);
                if (x.sign < 0)
                {
                    x = x.Add(mr);
                }
            }

            while (x.CompareTo(m) >= 0)
            {
                x = x.Subtract(m);
            }

            return x;
        }

        private static BigInteger ModPowMonty(BigInteger b, BigInteger e, BigInteger m, bool convert)
        {
            int n = m.magnitude.Length;
            int powR = 32 * n;
            bool smallMontyModulus = m.BitLength + 2 <= powR;
            uint mDash = (uint)m.GetMQuote();

            // tmp = this * R mod m
            if (convert)
            {
                b = b.ShiftLeft(powR).Remainder(m);
            }

            int[] yAccum = new int[n + 1];

            int[] zVal = b.magnitude;
            Debug.Assert(zVal.Length <= n);
            if (zVal.Length < n)
            {
                int[] tmp = new int[n];
                zVal.CopyTo(tmp, n - zVal.Length);
                zVal = tmp;
            }

            // Sliding window from MSW to LSW

            int extraBits = 0;

            // Filter the common case of small RSA exponents with few bits set
            if (e.magnitude.Length > 1 || e.BitCount > 2)
            {
                int expLength = e.BitLength;
                while (expLength > ExpWindowThresholds[extraBits])
                {
                    ++extraBits;
                }
            }

            int numPowers = 1 << extraBits;
            int[][] oddPowers = new int[numPowers][];
            oddPowers[0] = zVal;

            int[] zSquared = Arrays.Clone(zVal);
            SquareMonty(yAccum, zSquared, m.magnitude, mDash, smallMontyModulus);

            for (int i = 1; i < numPowers; ++i)
            {
                oddPowers[i] = Arrays.Clone(oddPowers[i - 1]);
                MultiplyMonty(yAccum, oddPowers[i], zSquared, m.magnitude, mDash, smallMontyModulus);
            }

            int[] windowList = GetWindowList(e.magnitude, extraBits);
            Debug.Assert(windowList.Length > 1);

            int window = windowList[0];
            int mult = window & 0xFF, lastZeroes = window >> 8;

            int[] yVal;
            if (mult == 1)
            {
                yVal = zSquared;
                --lastZeroes;
            }
            else
            {
                yVal = Arrays.Clone(oddPowers[mult >> 1]);
            }

            int windowPos = 1;
            while ((window = windowList[windowPos++]) != -1)
            {
                mult = window & 0xFF;

                int bits = lastZeroes + BitLengthTable[mult];
                for (int j = 0; j < bits; ++j)
                {
                    SquareMonty(yAccum, yVal, m.magnitude, mDash, smallMontyModulus);
                }

                MultiplyMonty(yAccum, yVal, oddPowers[mult >> 1], m.magnitude, mDash, smallMontyModulus);

                lastZeroes = window >> 8;
            }

            for (int i = 0; i < lastZeroes; ++i)
            {
                SquareMonty(yAccum, yVal, m.magnitude, mDash, smallMontyModulus);
            }

            if (convert)
            {
                // Return y * R^(-1) mod m
                MontgomeryReduce(yVal, m.magnitude, mDash);
            }
            else if (smallMontyModulus && CompareTo(0, yVal, 0, m.magnitude) >= 0)
            {
                Subtract(0, yVal, 0, m.magnitude);
            }

            return new BigInteger(1, yVal, true);
        }

        private static int[] GetWindowList(int[] mag, int extraBits)
        {
            int v = mag[0];
            Debug.Assert(v != 0);

            int leadingBits = BitLen(v);

            int resultSize = (((mag.Length - 1) << 5) + leadingBits) / (1 + extraBits) + 2;
            int[] result = new int[resultSize];
            int resultPos = 0;

            int bitPos = 33 - leadingBits;
            v <<= bitPos;

            int mult = 1, multLimit = 1 << extraBits;
            int zeroes = 0;

            int i = 0;
            for (; ; )
            {
                for (; bitPos < 32; ++bitPos)
                {
                    if (mult < multLimit)
                    {
                        mult = (mult << 1) | (int)((uint)v >> 31);
                    }
                    else if (v < 0)
                    {
                        result[resultPos++] = CreateWindowEntry(mult, zeroes);
                        mult = 1;
                        zeroes = 0;
                    }
                    else
                    {
                        ++zeroes;
                    }

                    v <<= 1;
                }

                if (++i == mag.Length)
                {
                    result[resultPos++] = CreateWindowEntry(mult, zeroes);
                    break;
                }

                v = mag[i];
                bitPos = 0;
            }

            result[resultPos] = -1;
            return result;
        }

        private static int CreateWindowEntry(int mult, int zeroes)
        {
            while ((mult & 1) == 0)
            {
                mult >>= 1;
                ++zeroes;
            }

            return mult | (zeroes << 8);
        }

        /**
         * return w with w = x * x - w is assumed to have enough space.
         */
        private static int[] Square(
            int[] w,
            int[] x)
        {
            // Note: this method allows w to be only (2 * x.Length - 1) words if result will fit
            //			if (w.Length != 2 * x.Length)
            //				throw new ArgumentException("no I don't think so...");

            ulong c;

            int wBase = w.Length - 1;

            for (int i = x.Length - 1; i > 0; --i)
            {
                ulong v = (uint)x[i];

                c = v * v + (uint)w[wBase];
                w[wBase] = (int)c;
                c >>= 32;

                for (int j = i - 1; j >= 0; --j)
                {
                    ulong prod = v * (uint)x[j];

                    c += ((uint)w[--wBase] & UIMASK) + ((uint)prod << 1);
                    w[wBase] = (int)c;
                    c = (c >> 32) + (prod >> 31);
                }

                c += (uint)w[--wBase];
                w[wBase] = (int)c;

                if (--wBase >= 0)
                {
                    w[wBase] = (int)(c >> 32);
                }
                else
                {
                    Debug.Assert((c >> 32) == 0);
                }

                wBase += i;
            }

            c = (uint)x[0];

            c = c * c + (uint)w[wBase];
            w[wBase] = (int)c;

            if (--wBase >= 0)
            {
                w[wBase] += (int)(c >> 32);
            }
            else
            {
                Debug.Assert((c >> 32) == 0);
            }

            return w;
        }

        /**
         * return x with x = y * z - x is assumed to have enough space.
         */
        private static int[] Multiply(int[] x, int[] y, int[] z)
        {
            int i = z.Length;

            if (i < 1)
                return x;

            int xBase = x.Length - y.Length;

            do
            {
                long a = z[--i] & IMASK;
                long val = 0;

                if (a != 0)
                {
                    for (int j = y.Length - 1; j >= 0; j--)
                    {
                        val += a * (y[j] & IMASK) + (x[xBase + j] & IMASK);

                        x[xBase + j] = (int)val;

                        val = (long)((ulong)val >> 32);
                    }
                }

                --xBase;

                if (xBase >= 0)
                {
                    x[xBase] = (int)val;
                }
                else
                {
                    Debug.Assert(val == 0);
                }
            }
            while (i > 0);

            return x;
        }

        /**
         * Calculate mQuote = -m^(-1) mod b with b = 2^32 (32 = word size)
         */
        private int GetMQuote()
        {
            if (mQuote != 0)
            {
                return mQuote; // already calculated
            }

            Debug.Assert(this.sign > 0);

            int d = -magnitude[magnitude.Length - 1];

            Debug.Assert((d & 1) != 0);

            return mQuote = ModInverse32(d);
        }

        private static void MontgomeryReduce(int[] x, int[] m, uint mDash) // mDash = -m^(-1) mod b
        {
            // NOTE: Not a general purpose reduction (which would allow x up to twice the bitlength of m)
            Debug.Assert(x.Length == m.Length);

            int n = m.Length;

            for (int i = n - 1; i >= 0; --i)
            {
                uint x0 = (uint)x[n - 1];
                ulong t = x0 * mDash;

                ulong carry = t * (uint)m[n - 1] + x0;
                Debug.Assert((uint)carry == 0);
                carry >>= 32;

                for (int j = n - 2; j >= 0; --j)
                {
                    carry += t * (uint)m[j] + (uint)x[j];
                    x[j + 1] = (int)carry;
                    carry >>= 32;
                }

                x[0] = (int)carry;
                Debug.Assert(carry >> 32 == 0);
            }

            if (CompareTo(0, x, 0, m) >= 0)
            {
                Subtract(0, x, 0, m);
            }
        }

        /**
         * Montgomery multiplication: a = x * y * R^(-1) mod m
         * <br/>
         * Based algorithm 14.36 of Handbook of Applied Cryptography.
         * <br/>
         * <li> m, x, y should have length n </li>
         * <li> a should have length (n + 1) </li>
         * <li> b = 2^32, R = b^n </li>
         * <br/>
         * The result is put in x
         * <br/>
         * NOTE: the indices of x, y, m, a different in HAC and in Java
         */
        private static void MultiplyMonty(int[] a, int[] x, int[] y, int[] m, uint mDash, bool smallMontyModulus)
        // mDash = -m^(-1) mod b
        {
            int n = m.Length;

            if (n == 1)
            {
                x[0] = (int)MultiplyMontyNIsOne((uint)x[0], (uint)y[0], (uint)m[0], mDash);
                return;
            }

            uint y0 = (uint)y[n - 1];
            int aMax;

            {
                ulong xi = (uint)x[n - 1];

                ulong carry = xi * y0;
                ulong t = (uint)carry * mDash;

                ulong prod2 = t * (uint)m[n - 1];
                carry += (uint)prod2;
                Debug.Assert((uint)carry == 0);
                carry = (carry >> 32) + (prod2 >> 32);

                for (int j = n - 2; j >= 0; --j)
                {
                    ulong prod1 = xi * (uint)y[j];
                    prod2 = t * (uint)m[j];

                    carry += (prod1 & UIMASK) + (uint)prod2;
                    a[j + 2] = (int)carry;
                    carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);
                }

                a[1] = (int)carry;
                aMax = (int)(carry >> 32);
            }

            for (int i = n - 2; i >= 0; --i)
            {
                uint a0 = (uint)a[n];
                ulong xi = (uint)x[i];

                ulong prod1 = xi * y0;
                ulong carry = (prod1 & UIMASK) + a0;
                ulong t = (uint)carry * mDash;

                ulong prod2 = t * (uint)m[n - 1];
                carry += (uint)prod2;
                Debug.Assert((uint)carry == 0);
                carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);

                for (int j = n - 2; j >= 0; --j)
                {
                    prod1 = xi * (uint)y[j];
                    prod2 = t * (uint)m[j];

                    carry += (prod1 & UIMASK) + (uint)prod2 + (uint)a[j + 1];
                    a[j + 2] = (int)carry;
                    carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);
                }

                carry += (uint)aMax;
                a[1] = (int)carry;
                aMax = (int)(carry >> 32);
            }

            a[0] = aMax;

            if (!smallMontyModulus && CompareTo(0, a, 0, m) >= 0)
            {
                Subtract(0, a, 0, m);
            }

            Array.Copy(a, 1, x, 0, n);
        }

        private static void SquareMonty(int[] a, int[] x, int[] m, uint mDash, bool smallMontyModulus)
        // mDash = -m^(-1) mod b
        {
            int n = m.Length;

            if (n == 1)
            {
                uint xVal = (uint)x[0];
                x[0] = (int)MultiplyMontyNIsOne(xVal, xVal, (uint)m[0], mDash);
                return;
            }

            ulong x0 = (uint)x[n - 1];
            int aMax;

            {
                ulong carry = x0 * x0;
                ulong t = (uint)carry * mDash;

                ulong prod2 = t * (uint)m[n - 1];
                carry += (uint)prod2;
                Debug.Assert((uint)carry == 0);
                carry = (carry >> 32) + (prod2 >> 32);

                for (int j = n - 2; j >= 0; --j)
                {
                    ulong prod1 = x0 * (uint)x[j];
                    prod2 = t * (uint)m[j];

                    carry += (prod2 & UIMASK) + ((uint)prod1 << 1);
                    a[j + 2] = (int)carry;
                    carry = (carry >> 32) + (prod1 >> 31) + (prod2 >> 32);
                }

                a[1] = (int)carry;
                aMax = (int)(carry >> 32);
            }

            for (int i = n - 2; i >= 0; --i)
            {
                uint a0 = (uint)a[n];
                ulong t = a0 * mDash;

                ulong carry = t * (uint)m[n - 1] + a0;
                Debug.Assert((uint)carry == 0);
                carry >>= 32;

                for (int j = n - 2; j > i; --j)
                {
                    carry += t * (uint)m[j] + (uint)a[j + 1];
                    a[j + 2] = (int)carry;
                    carry >>= 32;
                }

                ulong xi = (uint)x[i];

                {
                    ulong prod1 = xi * xi;
                    ulong prod2 = t * (uint)m[i];

                    carry += (prod1 & UIMASK) + (uint)prod2 + (uint)a[i + 1];
                    a[i + 2] = (int)carry;
                    carry = (carry >> 32) + (prod1 >> 32) + (prod2 >> 32);
                }

                for (int j = i - 1; j >= 0; --j)
                {
                    ulong prod1 = xi * (uint)x[j];
                    ulong prod2 = t * (uint)m[j];

                    carry += (prod2 & UIMASK) + ((uint)prod1 << 1) + (uint)a[j + 1];
                    a[j + 2] = (int)carry;
                    carry = (carry >> 32) + (prod1 >> 31) + (prod2 >> 32);
                }

                carry += (uint)aMax;
                a[1] = (int)carry;
                aMax = (int)(carry >> 32);
            }

            a[0] = aMax;

            if (!smallMontyModulus && CompareTo(0, a, 0, m) >= 0)
            {
                Subtract(0, a, 0, m);
            }

            Array.Copy(a, 1, x, 0, n);
        }

        private static uint MultiplyMontyNIsOne(uint x, uint y, uint m, uint mDash)
        {
            ulong carry = (ulong)x * y;
            uint t = (uint)carry * mDash;
            ulong um = m;
            ulong prod2 = um * t;
            carry += (uint)prod2;
            Debug.Assert((uint)carry == 0);
            carry = (carry >> 32) + (prod2 >> 32);
            if (carry > um)
            {
                carry -= um;
            }
            Debug.Assert(carry < um);
            return (uint)carry;
        }

        public BigInteger Multiply(
            BigInteger val)
        {
            if (val == this)
                return Square();

            if ((sign & val.sign) == 0)
                return Zero;

            if (val.QuickPow2Check()) // val is power of two
            {
                BigInteger result = this.ShiftLeft(val.Abs().BitLength - 1);
                return val.sign > 0 ? result : result.Negate();
            }

            if (this.QuickPow2Check()) // this is power of two
            {
                BigInteger result = val.ShiftLeft(this.Abs().BitLength - 1);
                return this.sign > 0 ? result : result.Negate();
            }

            int resLength = magnitude.Length + val.magnitude.Length;
            int[] res = new int[resLength];

            Multiply(res, this.magnitude, val.magnitude);

            int resSign = sign ^ val.sign ^ 1;
            return new BigInteger(resSign, res, true);
        }

        public BigInteger Square()
        {
            if (sign == 0)
                return Zero;
            if (this.QuickPow2Check())
                return ShiftLeft(Abs().BitLength - 1);
            int resLength = magnitude.Length << 1;
            if ((uint)magnitude[0] >> 16 == 0)
                --resLength;
            int[] res = new int[resLength];
            Square(res, magnitude);
            return new BigInteger(1, res, false);
        }

        public BigInteger Negate()
        {
            if (sign == 0)
                return this;

            return new BigInteger(-sign, magnitude, false);
        }

        public BigInteger NextProbablePrime()
        {
            if (sign < 0)
                throw new ArithmeticException("Cannot be called on value < 0");

            if (CompareTo(Two) < 0)
                return Two;

            BigInteger n = Inc().SetBit(0);

            while (!n.CheckProbablePrime(100, RandomSource, false))
            {
                n = n.Add(Two);
            }

            return n;
        }

        public BigInteger Not()
        {
            return Inc().Negate();
        }

        public BigInteger Pow(int exp)
        {
            if (exp <= 0)
            {
                if (exp < 0)
                    throw new ArithmeticException("Negative exponent");

                return One;
            }

            if (sign == 0)
            {
                return this;
            }

            if (QuickPow2Check())
            {
                long powOf2 = (long)exp * (BitLength - 1);
                if (powOf2 > Int32.MaxValue)
                {
                    throw new ArithmeticException("Result too large");
                }
                return One.ShiftLeft((int)powOf2);
            }

            BigInteger y = One;
            BigInteger z = this;

            for (; ; )
            {
                if ((exp & 0x1) == 1)
                {
                    y = y.Multiply(z);
                }
                exp >>= 1;
                if (exp == 0) break;
                z = z.Multiply(z);
            }

            return y;
        }

        public static BigInteger ProbablePrime(
            int bitLength,
            Random random)
        {
            return new BigInteger(bitLength, 100, random);
        }

        private int Remainder(
            int m)
        {
            Debug.Assert(m > 0);

            long acc = 0;
            for (int pos = 0; pos < magnitude.Length; ++pos)
            {
                long posVal = (uint)magnitude[pos];
                acc = (acc << 32 | posVal) % m;
            }

            return (int)acc;
        }

        /**
         * return x = x % y - done in place (y value preserved)
         */
        private static int[] Remainder(
            int[] x,
            int[] y)
        {
            int xStart = 0;
            while (xStart < x.Length && x[xStart] == 0)
            {
                ++xStart;
            }

            int yStart = 0;
            while (yStart < y.Length && y[yStart] == 0)
            {
                ++yStart;
            }

            Debug.Assert(yStart < y.Length);

            int xyCmp = CompareNoLeadingZeroes(xStart, x, yStart, y);

            if (xyCmp > 0)
            {
                int yBitLength = CalcBitLength(1, yStart, y);
                int xBitLength = CalcBitLength(1, xStart, x);
                int shift = xBitLength - yBitLength;

                int[] c;
                int cStart = 0;
                int cBitLength = yBitLength;
                if (shift > 0)
                {
                    c = ShiftLeft(y, shift);
                    cBitLength += shift;
                    Debug.Assert(c[0] != 0);
                }
                else
                {
                    int len = y.Length - yStart;
                    c = new int[len];
                    Array.Copy(y, yStart, c, 0, len);
                }

                for (; ; )
                {
                    if (cBitLength < xBitLength
                        || CompareNoLeadingZeroes(xStart, x, cStart, c) >= 0)
                    {
                        Subtract(xStart, x, cStart, c);

                        while (x[xStart] == 0)
                        {
                            if (++xStart == x.Length)
                                return x;
                        }

                        //xBitLength = CalcBitLength(xStart, x);
                        xBitLength = 32 * (x.Length - xStart - 1) + BitLen(x[xStart]);

                        if (xBitLength <= yBitLength)
                        {
                            if (xBitLength < yBitLength)
                                return x;

                            xyCmp = CompareNoLeadingZeroes(xStart, x, yStart, y);

                            if (xyCmp <= 0)
                                break;
                        }
                    }

                    shift = cBitLength - xBitLength;

                    // NB: The case where c[cStart] is 1-bit is harmless
                    if (shift == 1)
                    {
                        uint firstC = (uint)c[cStart] >> 1;
                        uint firstX = (uint)x[xStart];
                        if (firstC > firstX)
                            ++shift;
                    }

                    if (shift < 2)
                    {
                        ShiftRightOneInPlace(cStart, c);
                        --cBitLength;
                    }
                    else
                    {
                        ShiftRightInPlace(cStart, c, shift);
                        cBitLength -= shift;
                    }

                    //cStart = c.Length - ((cBitLength + 31) / 32);
                    while (c[cStart] == 0)
                    {
                        ++cStart;
                    }
                }
            }

            if (xyCmp == 0)
            {
                Array.Clear(x, xStart, x.Length - xStart);
            }

            return x;
        }

        public BigInteger Remainder(
            BigInteger n)
        {
            if (n.sign == 0)
                throw new ArithmeticException("Division by zero error");

            if (this.sign == 0)
                return Zero;

            // For small values, use fast remainder method
            if (n.magnitude.Length == 1)
            {
                int val = n.magnitude[0];

                if (val > 0)
                {
                    if (val == 1)
                        return Zero;

                    // TODO Make this func work on uint, and handle val == 1?
                    int rem = Remainder(val);

                    return rem == 0
                        ? Zero
                        : new BigInteger(sign, new int[] { rem }, false);
                }
            }

            if (CompareNoLeadingZeroes(0, magnitude, 0, n.magnitude) < 0)
                return this;

            int[] result;
            if (n.QuickPow2Check())  // n is power of two
            {
                // TODO Move before small values branch above?
                result = LastNBits(n.Abs().BitLength - 1);
            }
            else
            {
                result = (int[])this.magnitude.Clone();
                result = Remainder(result, n.magnitude);
            }

            return new BigInteger(sign, result, true);
        }

        private int[] LastNBits(
            int n)
        {
            if (n < 1)
                return ZeroMagnitude;

            int numWords = (n + BitsPerInt - 1) / BitsPerInt;
            numWords = System.Math.Min(numWords, this.magnitude.Length);
            int[] result = new int[numWords];

            Array.Copy(this.magnitude, this.magnitude.Length - numWords, result, 0, numWords);

            int excessBits = (numWords << 5) - n;
            if (excessBits > 0)
            {
                result[0] &= (int)(UInt32.MaxValue >> excessBits);
            }

            return result;
        }

        private BigInteger DivideWords(int w)
        {
            Debug.Assert(w >= 0);
            int n = magnitude.Length;
            if (w >= n)
                return Zero;
            int[] mag = new int[n - w];
            Array.Copy(magnitude, 0, mag, 0, n - w);
            return new BigInteger(sign, mag, false);
        }

        private BigInteger RemainderWords(int w)
        {
            Debug.Assert(w >= 0);
            int n = magnitude.Length;
            if (w >= n)
                return this;
            int[] mag = new int[w];
            Array.Copy(magnitude, n - w, mag, 0, w);
            return new BigInteger(sign, mag, false);
        }

        /**
         * do a left shift - this returns a new array.
         */
        private static int[] ShiftLeft(
            int[] mag,
            int n)
        {
            int nInts = (int)((uint)n >> 5);
            int nBits = n & 0x1f;
            int magLen = mag.Length;
            int[] newMag;

            if (nBits == 0)
            {
                newMag = new int[magLen + nInts];
                mag.CopyTo(newMag, 0);
            }
            else
            {
                int i = 0;
                int nBits2 = 32 - nBits;
                int highBits = (int)((uint)mag[0] >> nBits2);

                if (highBits != 0)
                {
                    newMag = new int[magLen + nInts + 1];
                    newMag[i++] = highBits;
                }
                else
                {
                    newMag = new int[magLen + nInts];
                }

                int m = mag[0];
                for (int j = 0; j < magLen - 1; j++)
                {
                    int next = mag[j + 1];

                    newMag[i++] = (m << nBits) | (int)((uint)next >> nBits2);
                    m = next;
                }

                newMag[i] = mag[magLen - 1] << nBits;
            }

            return newMag;
        }

        private static int ShiftLeftOneInPlace(int[] x, int carry)
        {
            Debug.Assert(carry == 0 || carry == 1);
            int pos = x.Length;
            while (--pos >= 0)
            {
                uint val = (uint)x[pos];
                x[pos] = (int)(val << 1) | carry;
                carry = (int)(val >> 31);
            }
            return carry;
        }

        public BigInteger ShiftLeft(
            int n)
        {
            if (sign == 0 || magnitude.Length == 0)
                return Zero;

            if (n == 0)
                return this;

            if (n < 0)
                return ShiftRight(-n);

            BigInteger result = new BigInteger(sign, ShiftLeft(magnitude, n), true);

            if (this.nBits != -1)
            {
                result.nBits = sign > 0
                    ? this.nBits
                    : this.nBits + n;
            }

            if (this.nBitLength != -1)
            {
                result.nBitLength = this.nBitLength + n;
            }

            return result;
        }

        /**
         * do a right shift - this does it in place.
         */
        private static void ShiftRightInPlace(
            int start,
            int[] mag,
            int n)
        {
            int nInts = (int)((uint)n >> 5) + start;
            int nBits = n & 0x1f;
            int magEnd = mag.Length - 1;

            if (nInts != start)
            {
                int delta = (nInts - start);

                for (int i = magEnd; i >= nInts; i--)
                {
                    mag[i] = mag[i - delta];
                }
                for (int i = nInts - 1; i >= start; i--)
                {
                    mag[i] = 0;
                }
            }

            if (nBits != 0)
            {
                int nBits2 = 32 - nBits;
                int m = mag[magEnd];

                for (int i = magEnd; i > nInts; --i)
                {
                    int next = mag[i - 1];

                    mag[i] = (int)((uint)m >> nBits) | (next << nBits2);
                    m = next;
                }

                mag[nInts] = (int)((uint)mag[nInts] >> nBits);
            }
        }

        /**
         * do a right shift by one - this does it in place.
         */
        private static void ShiftRightOneInPlace(
            int start,
            int[] mag)
        {
            int i = mag.Length;
            int m = mag[i - 1];

            while (--i > start)
            {
                int next = mag[i - 1];
                mag[i] = ((int)((uint)m >> 1)) | (next << 31);
                m = next;
            }

            mag[start] = (int)((uint)mag[start] >> 1);
        }

        public BigInteger ShiftRight(
            int n)
        {
            if (n == 0)
                return this;

            if (n < 0)
                return ShiftLeft(-n);

            if (n >= BitLength)
                return (this.sign < 0 ? One.Negate() : Zero);

            //			int[] res = (int[]) this.magnitude.Clone();
            //
            //			ShiftRightInPlace(0, res, n);
            //
            //			return new BigInteger(this.sign, res, true);

            int resultLength = (BitLength - n + 31) >> 5;
            int[] res = new int[resultLength];

            int numInts = n >> 5;
            int numBits = n & 31;

            if (numBits == 0)
            {
                Array.Copy(this.magnitude, 0, res, 0, res.Length);
            }
            else
            {
                int numBits2 = 32 - numBits;

                int magPos = this.magnitude.Length - 1 - numInts;
                for (int i = resultLength - 1; i >= 0; --i)
                {
                    res[i] = (int)((uint)this.magnitude[magPos--] >> numBits);

                    if (magPos >= 0)
                    {
                        res[i] |= this.magnitude[magPos] << numBits2;
                    }
                }
            }

            Debug.Assert(res[0] != 0);

            return new BigInteger(this.sign, res, false);
        }

        public int SignValue
        {
            get { return sign; }
        }

        /**
         * returns x = x - y - we assume x is >= y
         */
        private static int[] Subtract(
            int xStart,
            int[] x,
            int yStart,
            int[] y)
        {
            Debug.Assert(yStart < y.Length);
            Debug.Assert(x.Length - xStart >= y.Length - yStart);

            int iT = x.Length;
            int iV = y.Length;
            long m;
            int borrow = 0;

            do
            {
                m = (x[--iT] & IMASK) - (y[--iV] & IMASK) + borrow;
                x[iT] = (int)m;

                //				borrow = (m < 0) ? -1 : 0;
                borrow = (int)(m >> 63);
            }
            while (iV > yStart);

            if (borrow != 0)
            {
                while (--x[--iT] == -1)
                {
                }
            }

            return x;
        }

        public BigInteger Subtract(
            BigInteger n)
        {
            if (n.sign == 0)
                return this;

            if (this.sign == 0)
                return n.Negate();

            if (this.sign != n.sign)
                return Add(n.Negate());

            int compare = CompareNoLeadingZeroes(0, magnitude, 0, n.magnitude);
            if (compare == 0)
                return Zero;

            BigInteger bigun, lilun;
            if (compare < 0)
            {
                bigun = n;
                lilun = this;
            }
            else
            {
                bigun = this;
                lilun = n;
            }

            return new BigInteger(this.sign * compare, doSubBigLil(bigun.magnitude, lilun.magnitude), true);
        }

        private static int[] doSubBigLil(
            int[] bigMag,
            int[] lilMag)
        {
            int[] res = (int[])bigMag.Clone();

            return Subtract(0, res, 0, lilMag);
        }

        public byte[] ToByteArray()
        {
            return ToByteArray(false);
        }

        public byte[] ToByteArrayUnsigned()
        {
            return ToByteArray(true);
        }

        private byte[] ToByteArray(
            bool unsigned)
        {
            if (sign == 0)
                return unsigned ? ZeroEncoding : new byte[1];

            int nBits = (unsigned && sign > 0)
                ? BitLength
                : BitLength + 1;

            int nBytes = GetByteLength(nBits);
            byte[] bytes = new byte[nBytes];

            int magIndex = magnitude.Length;
            int bytesIndex = bytes.Length;

            if (sign > 0)
            {
                while (magIndex > 1)
                {
                    uint mag = (uint)magnitude[--magIndex];
                    bytes[--bytesIndex] = (byte)mag;
                    bytes[--bytesIndex] = (byte)(mag >> 8);
                    bytes[--bytesIndex] = (byte)(mag >> 16);
                    bytes[--bytesIndex] = (byte)(mag >> 24);
                }

                uint lastMag = (uint)magnitude[0];
                while (lastMag > byte.MaxValue)
                {
                    bytes[--bytesIndex] = (byte)lastMag;
                    lastMag >>= 8;
                }

                bytes[--bytesIndex] = (byte)lastMag;
            }
            else // sign < 0
            {
                bool carry = true;

                while (magIndex > 1)
                {
                    uint mag = ~((uint)magnitude[--magIndex]);

                    if (carry)
                    {
                        carry = (++mag == uint.MinValue);
                    }

                    bytes[--bytesIndex] = (byte)mag;
                    bytes[--bytesIndex] = (byte)(mag >> 8);
                    bytes[--bytesIndex] = (byte)(mag >> 16);
                    bytes[--bytesIndex] = (byte)(mag >> 24);
                }

                uint lastMag = (uint)magnitude[0];

                if (carry)
                {
                    // Never wraps because magnitude[0] != 0
                    --lastMag;
                }

                while (lastMag > byte.MaxValue)
                {
                    bytes[--bytesIndex] = (byte)~lastMag;
                    lastMag >>= 8;
                }

                bytes[--bytesIndex] = (byte)~lastMag;

                if (bytesIndex > 0)
                {
                    bytes[--bytesIndex] = byte.MaxValue;
                }
            }

            return bytes;
        }

        public override string ToString()
        {
            return ToString(10);
        }

        public string ToString(int radix)
        {
            // TODO Make this method work for other radices (ideally 2 <= radix <= 36 as in Java)

            switch (radix)
            {
                case 2:
                case 8:
                case 10:
                case 16:
                    break;
                default:
                    throw new FormatException("Only bases 2, 8, 10, 16 are allowed");
            }

            // NB: Can only happen to internally managed instances
            if (magnitude == null)
                return "null";

            if (sign == 0)
                return "0";


            // NOTE: This *should* be unnecessary, since the magnitude *should* never have leading zero digits
            int firstNonZero = 0;
            while (firstNonZero < magnitude.Length)
            {
                if (magnitude[firstNonZero] != 0)
                {
                    break;
                }
                ++firstNonZero;
            }

            if (firstNonZero == magnitude.Length)
            {
                return "0";
            }


            StringBuilder sb = new StringBuilder();
            if (sign == -1)
            {
                sb.Append('-');
            }

            switch (radix)
            {
                case 2:
                    {
                        int pos = firstNonZero;
                        sb.Append(Convert.ToString(magnitude[pos], 2));
                        while (++pos < magnitude.Length)
                        {
                            AppendZeroExtendedString(sb, Convert.ToString(magnitude[pos], 2), 32);
                        }
                        break;
                    }
                case 8:
                    {
                        int mask = (1 << 30) - 1;
                        BigInteger u = this.Abs();
                        int bits = u.BitLength;
                        IList S = Platform.CreateArrayList();
                        while (bits > 30)
                        {
                            S.Add(Convert.ToString(u.IntValue & mask, 8));
                            u = u.ShiftRight(30);
                            bits -= 30;
                        }
                        sb.Append(Convert.ToString(u.IntValue, 8));
                        for (int i = S.Count - 1; i >= 0; --i)
                        {
                            AppendZeroExtendedString(sb, (string)S[i], 10);
                        }
                        break;
                    }
                case 16:
                    {
                        int pos = firstNonZero;
                        sb.Append(Convert.ToString(magnitude[pos], 16));
                        while (++pos < magnitude.Length)
                        {
                            AppendZeroExtendedString(sb, Convert.ToString(magnitude[pos], 16), 8);
                        }
                        break;
                    }
                // TODO This could work for other radices if there is an alternative to Convert.ToString method
                //default:
                case 10:
                    {
                        BigInteger q = this.Abs();
                        if (q.BitLength < 64)
                        {
                            sb.Append(Convert.ToString(q.LongValue, radix));
                            break;
                        }

                        // TODO Could cache the moduli for each radix (soft reference?)
                        IList moduli = Platform.CreateArrayList();
                        BigInteger R = BigInteger.ValueOf(radix);
                        while (R.CompareTo(q) <= 0)
                        {
                            moduli.Add(R);
                            R = R.Square();
                        }

                        int scale = moduli.Count;
                        sb.EnsureCapacity(sb.Length + (1 << scale));

                        ToString(sb, radix, moduli, scale, q);

                        break;
                    }
            }

            return sb.ToString();
        }

        private static void ToString(StringBuilder sb, int radix, IList moduli, int scale, BigInteger pos)
        {
            if (pos.BitLength < 64)
            {
                string s = Convert.ToString(pos.LongValue, radix);
                if (sb.Length > 1 || (sb.Length == 1 && sb[0] != '-'))
                {
                    AppendZeroExtendedString(sb, s, 1 << scale);
                }
                else if (pos.SignValue != 0)
                {
                    sb.Append(s);
                }
                return;
            }

            BigInteger[] qr = pos.DivideAndRemainder((BigInteger)moduli[--scale]);

            ToString(sb, radix, moduli, scale, qr[0]);
            ToString(sb, radix, moduli, scale, qr[1]);
        }

        private static void AppendZeroExtendedString(StringBuilder sb, string s, int minLength)
        {
            for (int len = s.Length; len < minLength; ++len)
            {
                sb.Append('0');
            }
            sb.Append(s);
        }

        private static BigInteger CreateUValueOf(
            ulong value)
        {
            int msw = (int)(value >> 32);
            int lsw = (int)value;

            if (msw != 0)
                return new BigInteger(1, new int[] { msw, lsw }, false);

            if (lsw != 0)
            {
                BigInteger n = new BigInteger(1, new int[] { lsw }, false);
                // Check for a power of two
                if ((lsw & -lsw) == lsw)
                {
                    n.nBits = 1;
                }
                return n;
            }

            return Zero;
        }

        private static BigInteger CreateValueOf(
            long value)
        {
            if (value < 0)
            {
                if (value == long.MinValue)
                    return CreateValueOf(~value).Not();

                return CreateValueOf(-value).Negate();
            }

            return CreateUValueOf((ulong)value);
        }

        public static BigInteger ValueOf(
            long value)
        {
            if (value >= 0 && value < SMALL_CONSTANTS.Length)
            {
                return SMALL_CONSTANTS[value];
            }

            return CreateValueOf(value);
        }

        public int GetLowestSetBit()
        {
            if (this.sign == 0)
                return -1;

            return GetLowestSetBitMaskFirst(-1);
        }

        private int GetLowestSetBitMaskFirst(int firstWordMask)
        {
            int w = magnitude.Length, offset = 0;

            uint word = (uint)(magnitude[--w] & firstWordMask);
            Debug.Assert(magnitude[0] != 0);

            while (word == 0)
            {
                word = (uint)magnitude[--w];
                offset += 32;
            }

            while ((word & 0xFF) == 0)
            {
                word >>= 8;
                offset += 8;
            }

            while ((word & 1) == 0)
            {
                word >>= 1;
                ++offset;
            }

            return offset;
        }

        public bool TestBit(
            int n)
        {
            if (n < 0)
                throw new ArithmeticException("Bit position must not be negative");

            if (sign < 0)
                return !Not().TestBit(n);

            int wordNum = n / 32;
            if (wordNum >= magnitude.Length)
                return false;

            int word = magnitude[magnitude.Length - 1 - wordNum];
            return ((word >> (n % 32)) & 1) > 0;
        }

        public BigInteger Or(
            BigInteger value)
        {
            if (this.sign == 0)
                return value;

            if (value.sign == 0)
                return this;

            int[] aMag = this.sign > 0
                ? this.magnitude
                : Add(One).magnitude;

            int[] bMag = value.sign > 0
                ? value.magnitude
                : value.Add(One).magnitude;

            bool resultNeg = sign < 0 || value.sign < 0;
            int resultLength = System.Math.Max(aMag.Length, bMag.Length);
            int[] resultMag = new int[resultLength];

            int aStart = resultMag.Length - aMag.Length;
            int bStart = resultMag.Length - bMag.Length;

            for (int i = 0; i < resultMag.Length; ++i)
            {
                int aWord = i >= aStart ? aMag[i - aStart] : 0;
                int bWord = i >= bStart ? bMag[i - bStart] : 0;

                if (this.sign < 0)
                {
                    aWord = ~aWord;
                }

                if (value.sign < 0)
                {
                    bWord = ~bWord;
                }

                resultMag[i] = aWord | bWord;

                if (resultNeg)
                {
                    resultMag[i] = ~resultMag[i];
                }
            }

            BigInteger result = new BigInteger(1, resultMag, true);

            // TODO Optimise this case
            if (resultNeg)
            {
                result = result.Not();
            }

            return result;
        }

        public BigInteger Xor(
            BigInteger value)
        {
            if (this.sign == 0)
                return value;

            if (value.sign == 0)
                return this;

            int[] aMag = this.sign > 0
                ? this.magnitude
                : Add(One).magnitude;

            int[] bMag = value.sign > 0
                ? value.magnitude
                : value.Add(One).magnitude;

            // TODO Can just replace with sign != value.sign?
            bool resultNeg = (sign < 0 && value.sign >= 0) || (sign >= 0 && value.sign < 0);
            int resultLength = System.Math.Max(aMag.Length, bMag.Length);
            int[] resultMag = new int[resultLength];

            int aStart = resultMag.Length - aMag.Length;
            int bStart = resultMag.Length - bMag.Length;

            for (int i = 0; i < resultMag.Length; ++i)
            {
                int aWord = i >= aStart ? aMag[i - aStart] : 0;
                int bWord = i >= bStart ? bMag[i - bStart] : 0;

                if (this.sign < 0)
                {
                    aWord = ~aWord;
                }

                if (value.sign < 0)
                {
                    bWord = ~bWord;
                }

                resultMag[i] = aWord ^ bWord;

                if (resultNeg)
                {
                    resultMag[i] = ~resultMag[i];
                }
            }

            BigInteger result = new BigInteger(1, resultMag, true);

            // TODO Optimise this case
            if (resultNeg)
            {
                result = result.Not();
            }

            return result;
        }

        public BigInteger SetBit(
            int n)
        {
            if (n < 0)
                throw new ArithmeticException("Bit address less than zero");

            if (TestBit(n))
                return this;

            // TODO Handle negative values and zero
            if (sign > 0 && n < (BitLength - 1))
                return FlipExistingBit(n);

            return Or(One.ShiftLeft(n));
        }

        public BigInteger ClearBit(
            int n)
        {
            if (n < 0)
                throw new ArithmeticException("Bit address less than zero");

            if (!TestBit(n))
                return this;

            // TODO Handle negative values
            if (sign > 0 && n < (BitLength - 1))
                return FlipExistingBit(n);

            return AndNot(One.ShiftLeft(n));
        }

        public BigInteger FlipBit(
            int n)
        {
            if (n < 0)
                throw new ArithmeticException("Bit address less than zero");

            // TODO Handle negative values and zero
            if (sign > 0 && n < (BitLength - 1))
                return FlipExistingBit(n);

            return Xor(One.ShiftLeft(n));
        }

        private BigInteger FlipExistingBit(
            int n)
        {
            Debug.Assert(sign > 0);
            Debug.Assert(n >= 0);
            Debug.Assert(n < BitLength - 1);

            int[] mag = (int[])this.magnitude.Clone();
            mag[mag.Length - 1 - (n >> 5)] ^= (1 << (n & 31)); // Flip bit
            //mag[mag.Length - 1 - (n / 32)] ^= (1 << (n % 32));
            return new BigInteger(this.sign, mag, false);
        }
    }

    internal abstract class Platform
    {
        private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

#if NETCF_1_0 || NETCF_2_0
        private static string GetNewLine()
        {
            MemoryStream buf = new MemoryStream();
            StreamWriter w = new StreamWriter(buf, Encoding.UTF8);
            w.WriteLine();
            Dispose(w);
            byte[] bs = buf.ToArray();
            return Encoding.UTF8.GetString(bs, 0, bs.Length);
        }
#else
        private static string GetNewLine()
        {
            return Environment.NewLine;
        }
#endif

        internal static bool EqualsIgnoreCase(string a, string b)
        {
#if PORTABLE
            return String.Equals(a, b, StringComparison.OrdinalIgnoreCase);
#else
            return ToUpperInvariant(a) == ToUpperInvariant(b);
#endif
        }

#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE
        internal static string GetEnvironmentVariable(
            string variable)
        {
            return null;
        }
#else
        internal static string GetEnvironmentVariable(
            string variable)
        {
            try
            {
                return Environment.GetEnvironmentVariable(variable);
            }
            catch (System.Security.SecurityException)
            {
                // We don't have the required permission to read this environment variable,
                // which is fine, just act as if it's not set
                return null;
            }
        }
#endif

#if NETCF_1_0
        internal static Exception CreateNotImplementedException(
            string message)
        {
            return new Exception("Not implemented: " + message);
        }

        internal static bool Equals(
            object	a,
            object	b)
        {
            return a == b || (a != null && b != null && a.Equals(b));
        }
#else
        internal static Exception CreateNotImplementedException(
            string message)
        {
            return new NotImplementedException(message);
        }
#endif

#if SILVERLIGHT || PORTABLE
        internal static System.Collections.IList CreateArrayList()
        {
            return new List<object>();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new List<object>(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            System.Collections.IList result = new List<object>(collection.Count);
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            System.Collections.IList result = new List<object>();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Dictionary<object, object>();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Dictionary<object, object>(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            System.Collections.IDictionary result = new Dictionary<object, object>(dictionary.Count);
            foreach (System.Collections.DictionaryEntry entry in dictionary)
            {
                result.Add(entry.Key, entry.Value);
            }
            return result;
        }
#else
        internal static System.Collections.IList CreateArrayList()
        {
            return new ArrayList();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new ArrayList(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            return new ArrayList(collection);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            ArrayList result = new ArrayList();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Hashtable();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Hashtable(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            return new Hashtable(dictionary);
        }
#endif

        internal static string ToLowerInvariant(string s)
        {
#if PORTABLE
            return s.ToLowerInvariant();
#else
            return s.ToLower(CultureInfo.InvariantCulture);
#endif
        }

        internal static string ToUpperInvariant(string s)
        {
#if PORTABLE
            return s.ToUpperInvariant();
#else
            return s.ToUpper(CultureInfo.InvariantCulture);
#endif
        }

        internal static readonly string NewLine = GetNewLine();

#if PORTABLE
        internal static void Dispose(IDisposable d)
        {
            d.Dispose();
        }
#else
        internal static void Dispose(Stream s)
        {
            s.Close();
        }
        internal static void Dispose(TextWriter t)
        {
            t.Close();
        }
#endif

        internal static int IndexOf(string source, string value)
        {
            return InvariantCompareInfo.IndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static int LastIndexOf(string source, string value)
        {
            return InvariantCompareInfo.LastIndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static bool StartsWith(string source, string prefix)
        {
            return InvariantCompareInfo.IsPrefix(source, prefix, CompareOptions.Ordinal);
        }

        internal static bool EndsWith(string source, string suffix)
        {
            return InvariantCompareInfo.IsSuffix(source, suffix, CompareOptions.Ordinal);
        }

        internal static string GetTypeName(object obj)
        {
            return obj.GetType().FullName;
        }
    }

    public abstract class Arrays
    {
        public static bool AreEqual(
            bool[] a,
            bool[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        public static bool AreEqual(
            char[] a,
            char[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        /// <summary>
        /// Are two arrays equal.
        /// </summary>
        /// <param name="a">Left side.</param>
        /// <param name="b">Right side.</param>
        /// <returns>True if equal.</returns>
        public static bool AreEqual(
            byte[] a,
            byte[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        [Obsolete("Use 'AreEqual' method instead")]
        public static bool AreSame(
            byte[] a,
            byte[] b)
        {
            return AreEqual(a, b);
        }

        /// <summary>
        /// A constant time equals comparison - does not terminate early if
        /// test will fail.
        /// </summary>
        /// <param name="a">first array</param>
        /// <param name="b">second array</param>
        /// <returns>true if arrays equal, false otherwise.</returns>
        public static bool ConstantTimeAreEqual(
            byte[] a,
            byte[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            int cmp = 0;
            while (i != 0)
            {
                --i;
                cmp |= (a[i] ^ b[i]);
            }
            return cmp == 0;
        }

        public static bool AreEqual(
            int[] a,
            int[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        public static bool AreEqual(uint[] a, uint[] b)
        {
            if (a == b)
                return true;

            if (a == null || b == null)
                return false;

            return HaveSameContents(a, b);
        }

        private static bool HaveSameContents(
            bool[] a,
            bool[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(
            char[] a,
            char[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(
            byte[] a,
            byte[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(
            int[] a,
            int[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        private static bool HaveSameContents(uint[] a, uint[] b)
        {
            int i = a.Length;
            if (i != b.Length)
                return false;
            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        public static string ToString(
            object[] a)
        {
            StringBuilder sb = new StringBuilder('[');
            if (a.Length > 0)
            {
                sb.Append(a[0]);
                for (int index = 1; index < a.Length; ++index)
                {
                    sb.Append(", ").Append(a[index]);
                }
            }
            sb.Append(']');
            return sb.ToString();
        }

        public static int GetHashCode(byte[] data)
        {
            if (data == null)
            {
                return 0;
            }

            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
        }

        public static int GetHashCode(byte[] data, int off, int len)
        {
            if (data == null)
            {
                return 0;
            }

            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[off + i];
            }

            return hc;
        }

        public static int GetHashCode(int[] data)
        {
            if (data == null)
                return 0;

            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[i];
            }

            return hc;
        }

        public static int GetHashCode(int[] data, int off, int len)
        {
            if (data == null)
                return 0;

            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= data[off + i];
            }

            return hc;
        }

        [CLSCompliantAttribute(false)]
        public static int GetHashCode(uint[] data)
        {
            if (data == null)
                return 0;

            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= (int)data[i];
            }

            return hc;
        }

        [CLSCompliantAttribute(false)]
        public static int GetHashCode(uint[] data, int off, int len)
        {
            if (data == null)
                return 0;

            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= (int)data[off + i];
            }

            return hc;
        }

        [CLSCompliantAttribute(false)]
        public static int GetHashCode(ulong[] data)
        {
            if (data == null)
                return 0;

            int i = data.Length;
            int hc = i + 1;

            while (--i >= 0)
            {
                ulong di = data[i];
                hc *= 257;
                hc ^= (int)di;
                hc *= 257;
                hc ^= (int)(di >> 32);
            }

            return hc;
        }

        [CLSCompliantAttribute(false)]
        public static int GetHashCode(ulong[] data, int off, int len)
        {
            if (data == null)
                return 0;

            int i = len;
            int hc = i + 1;

            while (--i >= 0)
            {
                ulong di = data[off + i];
                hc *= 257;
                hc ^= (int)di;
                hc *= 257;
                hc ^= (int)(di >> 32);
            }

            return hc;
        }

        public static byte[] Clone(
            byte[] data)
        {
            return data == null ? null : (byte[])data.Clone();
        }

        public static byte[] Clone(
            byte[] data,
            byte[] existing)
        {
            if (data == null)
            {
                return null;
            }
            if ((existing == null) || (existing.Length != data.Length))
            {
                return Clone(data);
            }
            Array.Copy(data, 0, existing, 0, existing.Length);
            return existing;
        }

        public static int[] Clone(
            int[] data)
        {
            return data == null ? null : (int[])data.Clone();
        }

        internal static uint[] Clone(uint[] data)
        {
            return data == null ? null : (uint[])data.Clone();
        }

        public static long[] Clone(long[] data)
        {
            return data == null ? null : (long[])data.Clone();
        }

        [CLSCompliantAttribute(false)]
        public static ulong[] Clone(
            ulong[] data)
        {
            return data == null ? null : (ulong[])data.Clone();
        }

        [CLSCompliantAttribute(false)]
        public static ulong[] Clone(
            ulong[] data,
            ulong[] existing)
        {
            if (data == null)
            {
                return null;
            }
            if ((existing == null) || (existing.Length != data.Length))
            {
                return Clone(data);
            }
            Array.Copy(data, 0, existing, 0, existing.Length);
            return existing;
        }

        public static bool Contains(byte[] a, byte n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        public static bool Contains(short[] a, short n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        public static bool Contains(int[] a, int n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                    return true;
            }
            return false;
        }

        public static void Fill(
            byte[] buf,
            byte b)
        {
            int i = buf.Length;
            while (i > 0)
            {
                buf[--i] = b;
            }
        }

        public static byte[] CopyOf(byte[] data, int newLength)
        {
            byte[] tmp = new byte[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static char[] CopyOf(char[] data, int newLength)
        {
            char[] tmp = new char[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static int[] CopyOf(int[] data, int newLength)
        {
            int[] tmp = new int[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static long[] CopyOf(long[] data, int newLength)
        {
            long[] tmp = new long[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        public static BigInteger[] CopyOf(BigInteger[] data, int newLength)
        {
            BigInteger[] tmp = new BigInteger[newLength];
            Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
            return tmp;
        }

        /**
         * Make a copy of a range of bytes from the passed in data array. The range can
         * extend beyond the end of the input array, in which case the return array will
         * be padded with zeroes.
         *
         * @param data the array from which the data is to be copied.
         * @param from the start index at which the copying should take place.
         * @param to the final index of the range (exclusive).
         *
         * @return a new byte array containing the range given.
         */
        public static byte[] CopyOfRange(byte[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            byte[] tmp = new byte[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        public static int[] CopyOfRange(int[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            int[] tmp = new int[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        public static long[] CopyOfRange(long[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            long[] tmp = new long[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        public static BigInteger[] CopyOfRange(BigInteger[] data, int from, int to)
        {
            int newLength = GetLength(from, to);
            BigInteger[] tmp = new BigInteger[newLength];
            Array.Copy(data, from, tmp, 0, System.Math.Min(newLength, data.Length - from));
            return tmp;
        }

        private static int GetLength(int from, int to)
        {
            int newLength = to - from;
            if (newLength < 0)
                throw new ArgumentException(from + " > " + to);
            return newLength;
        }

        public static byte[] Append(byte[] a, byte b)
        {
            if (a == null)
                return new byte[] { b };

            int length = a.Length;
            byte[] result = new byte[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static short[] Append(short[] a, short b)
        {
            if (a == null)
                return new short[] { b };

            int length = a.Length;
            short[] result = new short[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static int[] Append(int[] a, int b)
        {
            if (a == null)
                return new int[] { b };

            int length = a.Length;
            int[] result = new int[length + 1];
            Array.Copy(a, 0, result, 0, length);
            result[length] = b;
            return result;
        }

        public static byte[] Concatenate(byte[] a, byte[] b)
        {
            if (a == null)
                return Clone(b);
            if (b == null)
                return Clone(a);

            byte[] rv = new byte[a.Length + b.Length];
            Array.Copy(a, 0, rv, 0, a.Length);
            Array.Copy(b, 0, rv, a.Length, b.Length);
            return rv;
        }

        public static byte[] ConcatenateAll(params byte[][] vs)
        {
            byte[][] nonNull = new byte[vs.Length][];
            int count = 0;
            int totalLength = 0;

            for (int i = 0; i < vs.Length; ++i)
            {
                byte[] v = vs[i];
                if (v != null)
                {
                    nonNull[count++] = v;
                    totalLength += v.Length;
                }
            }

            byte[] result = new byte[totalLength];
            int pos = 0;

            for (int j = 0; j < count; ++j)
            {
                byte[] v = nonNull[j];
                Array.Copy(v, 0, result, pos, v.Length);
                pos += v.Length;
            }

            return result;
        }

        public static int[] Concatenate(int[] a, int[] b)
        {
            if (a == null)
                return Clone(b);
            if (b == null)
                return Clone(a);

            int[] rv = new int[a.Length + b.Length];
            Array.Copy(a, 0, rv, 0, a.Length);
            Array.Copy(b, 0, rv, a.Length, b.Length);
            return rv;
        }

        public static byte[] Prepend(byte[] a, byte b)
        {
            if (a == null)
                return new byte[] { b };

            int length = a.Length;
            byte[] result = new byte[length + 1];
            Array.Copy(a, 0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static short[] Prepend(short[] a, short b)
        {
            if (a == null)
                return new short[] { b };

            int length = a.Length;
            short[] result = new short[length + 1];
            Array.Copy(a, 0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static int[] Prepend(int[] a, int b)
        {
            if (a == null)
                return new int[] { b };

            int length = a.Length;
            int[] result = new int[length + 1];
            Array.Copy(a, 0, result, 1, length);
            result[0] = b;
            return result;
        }

        public static byte[] Reverse(byte[] a)
        {
            if (a == null)
                return null;

            int p1 = 0, p2 = a.Length;
            byte[] result = new byte[p2];

            while (--p2 >= 0)
            {
                result[p2] = a[p1++];
            }

            return result;
        }

        public static int[] Reverse(int[] a)
        {
            if (a == null)
                return null;

            int p1 = 0, p2 = a.Length;
            int[] result = new int[p2];

            while (--p2 >= 0)
            {
                result[p2] = a[p1++];
            }

            return result;
        }
    }

    public class SecureRandom
        : Random
    {
        private static long counter = Times.NanoTime();
        private static long NextCounterValue()
        {
            return Interlocked.Increment(ref counter);
        }

        private static readonly SecureRandom master = new SecureRandom(new CryptoApiRandomGenerator());
        private static SecureRandom Master
        {
            get { return master; }
        }

        private static DigestRandomGenerator CreatePrng(string digestName, bool autoSeed)
        {
            IDigest digest = DigestUtilities.GetDigest(digestName);
            if (digest == null)
                return null;
            DigestRandomGenerator prng = new DigestRandomGenerator(digest);
            if (autoSeed)
            {
                prng.AddSeedMaterial(NextCounterValue());
                prng.AddSeedMaterial(GetNextBytes(Master, digest.GetDigestSize()));
            }
            return prng;
        }

        public static byte[] GetNextBytes(SecureRandom secureRandom, int length)
        {
            byte[] result = new byte[length];
            secureRandom.NextBytes(result);
            return result;
        }

        /// <summary>
        /// Create and auto-seed an instance based on the given algorithm.
        /// </summary>
        /// <remarks>Equivalent to GetInstance(algorithm, true)</remarks>
        /// <param name="algorithm">e.g. "SHA256PRNG"</param>
        public static SecureRandom GetInstance(string algorithm)
        {
            return GetInstance(algorithm, true);
        }

        /// <summary>
        /// Create an instance based on the given algorithm, with optional auto-seeding
        /// </summary>
        /// <param name="algorithm">e.g. "SHA256PRNG"</param>
        /// <param name="autoSeed">If true, the instance will be auto-seeded.</param>
        public static SecureRandom GetInstance(string algorithm, bool autoSeed)
        {
            string upper = Platform.ToUpperInvariant(algorithm);
            if (Platform.EndsWith(upper, "PRNG"))
            {
                string digestName = upper.Substring(0, upper.Length - "PRNG".Length);
                DigestRandomGenerator prng = CreatePrng(digestName, autoSeed);
                if (prng != null)
                {
                    return new SecureRandom(prng);
                }
            }

            throw new ArgumentException("Unrecognised PRNG algorithm: " + algorithm, "algorithm");
        }

        [Obsolete("Call GenerateSeed() on a SecureRandom instance instead")]
        public static byte[] GetSeed(int length)
        {
            return GetNextBytes(Master, length);
        }

        protected readonly IRandomGenerator generator;

        public SecureRandom()
            : this(CreatePrng("SHA256", true))
        {
        }

        /// <remarks>
        /// To replicate existing predictable output, replace with GetInstance("SHA1PRNG", false), followed by SetSeed(seed)
        /// </remarks>
        [Obsolete("Use GetInstance/SetSeed instead")]
        public SecureRandom(byte[] seed)
            : this(CreatePrng("SHA1", false))
        {
            SetSeed(seed);
        }

        /// <summary>Use the specified instance of IRandomGenerator as random source.</summary>
        /// <remarks>
        /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
        /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
        /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
        /// implementation.
        /// </remarks>
        /// <param name="generator">The source to generate all random bytes from.</param>
        public SecureRandom(IRandomGenerator generator)
            : base(0)
        {
            this.generator = generator;
        }

        public virtual byte[] GenerateSeed(int length)
        {
            return GetNextBytes(Master, length);
        }

        public virtual void SetSeed(byte[] seed)
        {
            generator.AddSeedMaterial(seed);
        }

        public virtual void SetSeed(long seed)
        {
            generator.AddSeedMaterial(seed);
        }

        public override int Next()
        {
            return NextInt() & int.MaxValue;
        }

        public override int Next(int maxValue)
        {

            if (maxValue < 2)
            {
                if (maxValue < 0)
                    throw new ArgumentOutOfRangeException("maxValue", "cannot be negative");

                return 0;
            }

            int bits;

            // Test whether maxValue is a power of 2
            if ((maxValue & (maxValue - 1)) == 0)
            {
                bits = NextInt() & int.MaxValue;
                return (int)(((long)bits * maxValue) >> 31);
            }

            int result;
            do
            {
                bits = NextInt() & int.MaxValue;
                result = bits % maxValue;
            }
            while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

            return result;
        }

        public override int Next(int minValue, int maxValue)
        {
            if (maxValue <= minValue)
            {
                if (maxValue == minValue)
                    return minValue;

                throw new ArgumentException("maxValue cannot be less than minValue");
            }

            int diff = maxValue - minValue;
            if (diff > 0)
                return minValue + Next(diff);

            for (; ; )
            {
                int i = NextInt();

                if (i >= minValue && i < maxValue)
                    return i;
            }
        }

        public override void NextBytes(byte[] buf)
        {
            generator.NextBytes(buf);
        }

        public virtual void NextBytes(byte[] buf, int off, int len)
        {
            generator.NextBytes(buf, off, len);
        }

        private static readonly double DoubleScale = System.Math.Pow(2.0, 64.0);

        public override double NextDouble()
        {
            return Convert.ToDouble((ulong)NextLong()) / DoubleScale;
        }

        public virtual int NextInt()
        {
            byte[] bytes = new byte[4];
            NextBytes(bytes);

            uint result = bytes[0];
            result <<= 8;
            result |= bytes[1];
            result <<= 8;
            result |= bytes[2];
            result <<= 8;
            result |= bytes[3];
            return (int)result;
        }

        public virtual long NextLong()
        {
            return ((long)(uint)NextInt() << 32) | (long)(uint)NextInt();
        }
    }

    /**
	 * Random generation based on the digest with counter. Calling AddSeedMaterial will
	 * always increase the entropy of the hash.
	 * <p>
	 * Internal access to the digest is synchronized so a single one of these can be shared.
	 * </p>
	 */
    public class DigestRandomGenerator
        : IRandomGenerator
    {
        private const long CYCLE_COUNT = 10;

        private long stateCounter;
        private long seedCounter;
        private IDigest digest;
        private byte[] state;
        private byte[] seed;

        public DigestRandomGenerator(
            IDigest digest)
        {
            this.digest = digest;

            this.seed = new byte[digest.GetDigestSize()];
            this.seedCounter = 1;

            this.state = new byte[digest.GetDigestSize()];
            this.stateCounter = 1;
        }

        public void AddSeedMaterial(
            byte[] inSeed)
        {
            lock (this)
            {
                DigestUpdate(inSeed);
                DigestUpdate(seed);
                DigestDoFinal(seed);
            }
        }

        public void AddSeedMaterial(
            long rSeed)
        {
            lock (this)
            {
                DigestAddCounter(rSeed);
                DigestUpdate(seed);
                DigestDoFinal(seed);
            }
        }

        public void NextBytes(
            byte[] bytes)
        {
            NextBytes(bytes, 0, bytes.Length);
        }

        public void NextBytes(
            byte[] bytes,
            int start,
            int len)
        {
            lock (this)
            {
                int stateOff = 0;

                GenerateState();

                int end = start + len;
                for (int i = start; i < end; ++i)
                {
                    if (stateOff == state.Length)
                    {
                        GenerateState();
                        stateOff = 0;
                    }
                    bytes[i] = state[stateOff++];
                }
            }
        }

        private void CycleSeed()
        {
            DigestUpdate(seed);
            DigestAddCounter(seedCounter++);
            DigestDoFinal(seed);
        }

        private void GenerateState()
        {
            DigestAddCounter(stateCounter++);
            DigestUpdate(state);
            DigestUpdate(seed);
            DigestDoFinal(state);

            if ((stateCounter % CYCLE_COUNT) == 0)
            {
                CycleSeed();
            }
        }

        private void DigestAddCounter(long seedVal)
        {
            byte[] bytes = new byte[8];
            Pack.UInt64_To_LE((ulong)seedVal, bytes);
            digest.BlockUpdate(bytes, 0, bytes.Length);
        }

        private void DigestUpdate(byte[] inSeed)
        {
            digest.BlockUpdate(inSeed, 0, inSeed.Length);
        }

        private void DigestDoFinal(byte[] result)
        {
            digest.DoFinal(result, 0);
        }

        /// <remarks>Generic interface for objects generating random bytes.</remarks>
        public interface IRandomGenerator
        {
            /// <summary>Add more seed material to the generator.</summary>
            /// <param name="seed">A byte array to be mixed into the generator's state.</param>
            void AddSeedMaterial(byte[] seed);

            /// <summary>Add more seed material to the generator.</summary>
            /// <param name="seed">A long value to be mixed into the generator's state.</param>
            void AddSeedMaterial(long seed);

            /// <summary>Fill byte array with random values.</summary>
            /// <param name="bytes">Array to be filled.</param>
            void NextBytes(byte[] bytes);

            /// <summary>Fill byte array with random values.</summary>
            /// <param name="bytes">Array to receive bytes.</param>
            /// <param name="start">Index to start filling at.</param>
            /// <param name="len">Length of segment to fill.</param>
            void NextBytes(byte[] bytes, int start, int len);
        }
    }
    public interface IDigest
    {
        /**
         * return the algorithm name
         *
         * @return the algorithm name
         */
        string AlgorithmName { get; }

        /**
         * return the size, in bytes, of the digest produced by this message digest.
         *
         * @return the size, in bytes, of the digest produced by this message digest.
         */
        int GetDigestSize();

        /**
         * return the size, in bytes, of the internal buffer used by this digest.
         *
         * @return the size, in bytes, of the internal buffer used by this digest.
         */
        int GetByteLength();

        /**
         * update the message digest with a single byte.
         *
         * @param inByte the input byte to be entered.
         */
        void Update(byte input);

        /**
         * update the message digest with a block of bytes.
         *
         * @param input the byte array containing the data.
         * @param inOff the offset into the byte array where the data starts.
         * @param len the length of the data.
         */
        void BlockUpdate(byte[] input, int inOff, int length);

        /**
         * Close the digest, producing the final digest value. The doFinal
         * call leaves the digest reset.
         *
         * @param output the array the digest is to be copied into.
         * @param outOff the offset into the out array the digest is to start at.
         */
        int DoFinal(byte[] output, int outOff);

        /**
         * reset the digest back to it's initial state.
         */
        void Reset();
    }

    /// <summary>
    /// Uses RandomNumberGenerator.Create() to get randomness generator
    /// </summary>
    public class CryptoApiRandomGenerator
        : IRandomGenerator
    {
        private readonly RandomNumberGenerator rndProv;

        public CryptoApiRandomGenerator()
            : this(RandomNumberGenerator.Create())
        {
        }

        public CryptoApiRandomGenerator(RandomNumberGenerator rng)
        {
            this.rndProv = rng;
        }

        #region IRandomGenerator Members

        public virtual void AddSeedMaterial(byte[] seed)
        {
            // We don't care about the seed
        }

        public virtual void AddSeedMaterial(long seed)
        {
            // We don't care about the seed
        }

        public virtual void NextBytes(byte[] bytes)
        {
            rndProv.GetBytes(bytes);
        }

        public virtual void NextBytes(byte[] bytes, int start, int len)
        {
            if (start < 0)
                throw new ArgumentException("Start offset cannot be negative", "start");
            if (bytes.Length < (start + len))
                throw new ArgumentException("Byte array too small for requested offset and length");

            if (bytes.Length == len && start == 0)
            {
                NextBytes(bytes);
            }
            else
            {
                byte[] tmpBuf = new byte[len];
                NextBytes(tmpBuf);
                Array.Copy(tmpBuf, 0, bytes, start, len);
            }
        }

        #endregion
    }

    public sealed class Times
    {
        private static long NanosecondsPerTick = 100L;

        public static long NanoTime()
        {
            return DateTime.UtcNow.Ticks * NanosecondsPerTick;
        }
    }

    public sealed class DigestUtilities
    {
        private enum DigestAlgorithm
        {
            BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512,
            BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE2S_256,
            DSTU7564_256, DSTU7564_384, DSTU7564_512,
            GOST3411,
            GOST3411_2012_256, GOST3411_2012_512,
            KECCAK_224, KECCAK_256, KECCAK_288, KECCAK_384, KECCAK_512,
            MD2, MD4, MD5,
            RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320,
            SHA_1, SHA_224, SHA_256, SHA_384, SHA_512,
            SHA_512_224, SHA_512_256,
            SHA3_224, SHA3_256, SHA3_384, SHA3_512,
            SHAKE128, SHAKE256,
            SM3,
            TIGER,
            WHIRLPOOL,
        };

        private DigestUtilities()
        {
        }

        private static readonly IDictionary algorithms = Platform.CreateHashtable();
        private static readonly IDictionary oids = Platform.CreateHashtable();


        public static ICollection Algorithms
        {
            get { return oids.Keys; }
        }

        public static IDigest GetDigest(
            string algorithm)
        {
            Sha256Digest sha256 = new Sha256Digest();
            return (IDigest)sha256;
        }
    }


    public class Sha256Digest
        : GeneralDigest
    {
        private const int DigestLength = 32;

        private uint H1, H2, H3, H4, H5, H6, H7, H8;
        private uint[] X = new uint[64];
        private int xOff;

        public Sha256Digest()
        {
            initHs();
        }

        /**
        * Copy constructor.  This will copy the state of the provided
        * message digest.
        */
        public Sha256Digest(Sha256Digest t) : base(t)
        {
            CopyIn(t);
        }

        private void CopyIn(Sha256Digest t)
        {
            base.CopyIn(t);

            H1 = t.H1;
            H2 = t.H2;
            H3 = t.H3;
            H4 = t.H4;
            H5 = t.H5;
            H6 = t.H6;
            H7 = t.H7;
            H8 = t.H8;

            Array.Copy(t.X, 0, X, 0, t.X.Length);
            xOff = t.xOff;
        }

        public override string AlgorithmName
        {
            get { return "SHA-256"; }
        }

        public override int GetDigestSize()
        {
            return DigestLength;
        }

        internal override void ProcessWord(
            byte[] input,
            int inOff)
        {
            X[xOff] = Pack.BE_To_UInt32(input, inOff);

            if (++xOff == 16)
            {
                ProcessBlock();
            }
        }

        internal override void ProcessLength(
            long bitLength)
        {
            if (xOff > 14)
            {
                ProcessBlock();
            }

            X[14] = (uint)((ulong)bitLength >> 32);
            X[15] = (uint)((ulong)bitLength);
        }

        public override int DoFinal(
            byte[] output,
            int outOff)
        {
            Finish();

            Pack.UInt32_To_BE((uint)H1, output, outOff);
            Pack.UInt32_To_BE((uint)H2, output, outOff + 4);
            Pack.UInt32_To_BE((uint)H3, output, outOff + 8);
            Pack.UInt32_To_BE((uint)H4, output, outOff + 12);
            Pack.UInt32_To_BE((uint)H5, output, outOff + 16);
            Pack.UInt32_To_BE((uint)H6, output, outOff + 20);
            Pack.UInt32_To_BE((uint)H7, output, outOff + 24);
            Pack.UInt32_To_BE((uint)H8, output, outOff + 28);

            Reset();

            return DigestLength;
        }

        /**
        * reset the chaining variables
        */
        public override void Reset()
        {
            base.Reset();

            initHs();

            xOff = 0;
            Array.Clear(X, 0, X.Length);
        }

        private void initHs()
        {
            /* SHA-256 initial hash value
            * The first 32 bits of the fractional parts of the square roots
            * of the first eight prime numbers
            */
            H1 = 0x6a09e667;
            H2 = 0xbb67ae85;
            H3 = 0x3c6ef372;
            H4 = 0xa54ff53a;
            H5 = 0x510e527f;
            H6 = 0x9b05688c;
            H7 = 0x1f83d9ab;
            H8 = 0x5be0cd19;
        }

        internal override void ProcessBlock()
        {
            //
            // expand 16 word block into 64 word blocks.
            //
            for (int ti = 16; ti <= 63; ti++)
            {
                X[ti] = Theta1(X[ti - 2]) + X[ti - 7] + Theta0(X[ti - 15]) + X[ti - 16];
            }

            //
            // set up working variables.
            //
            uint a = H1;
            uint b = H2;
            uint c = H3;
            uint d = H4;
            uint e = H5;
            uint f = H6;
            uint g = H7;
            uint h = H8;

            int t = 0;
            for (int i = 0; i < 8; ++i)
            {
                // t = 8 * i
                h += Sum1Ch(e, f, g) + K[t] + X[t];
                d += h;
                h += Sum0Maj(a, b, c);
                ++t;

                // t = 8 * i + 1
                g += Sum1Ch(d, e, f) + K[t] + X[t];
                c += g;
                g += Sum0Maj(h, a, b);
                ++t;

                // t = 8 * i + 2
                f += Sum1Ch(c, d, e) + K[t] + X[t];
                b += f;
                f += Sum0Maj(g, h, a);
                ++t;

                // t = 8 * i + 3
                e += Sum1Ch(b, c, d) + K[t] + X[t];
                a += e;
                e += Sum0Maj(f, g, h);
                ++t;

                // t = 8 * i + 4
                d += Sum1Ch(a, b, c) + K[t] + X[t];
                h += d;
                d += Sum0Maj(e, f, g);
                ++t;

                // t = 8 * i + 5
                c += Sum1Ch(h, a, b) + K[t] + X[t];
                g += c;
                c += Sum0Maj(d, e, f);
                ++t;

                // t = 8 * i + 6
                b += Sum1Ch(g, h, a) + K[t] + X[t];
                f += b;
                b += Sum0Maj(c, d, e);
                ++t;

                // t = 8 * i + 7
                a += Sum1Ch(f, g, h) + K[t] + X[t];
                e += a;
                a += Sum0Maj(b, c, d);
                ++t;
            }

            H1 += a;
            H2 += b;
            H3 += c;
            H4 += d;
            H5 += e;
            H6 += f;
            H7 += g;
            H8 += h;

            //
            // reset the offset and clean out the word buffer.
            //
            xOff = 0;
            Array.Clear(X, 0, 16);
        }

        private static uint Sum1Ch(
            uint x,
            uint y,
            uint z)
        {
            //			return Sum1(x) + Ch(x, y, z);
            return (((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7)))
                + ((x & y) ^ ((~x) & z));
        }

        private static uint Sum0Maj(
            uint x,
            uint y,
            uint z)
        {
            //			return Sum0(x) + Maj(x, y, z);
            return (((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10)))
                + ((x & y) ^ (x & z) ^ (y & z));
        }

        //		/* SHA-256 functions */
        //        private static uint Ch(
        //            uint    x,
        //            uint    y,
        //            uint    z)
        //        {
        //            return ((x & y) ^ ((~x) & z));
        //        }
        //
        //        private static uint Maj(
        //            uint	x,
        //            uint    y,
        //            uint    z)
        //        {
        //            return ((x & y) ^ (x & z) ^ (y & z));
        //        }
        //
        //        private static uint Sum0(
        //            uint x)
        //        {
        //	        return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));
        //        }
        //
        //        private static uint Sum1(
        //            uint x)
        //        {
        //	        return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));
        //        }

        private static uint Theta0(
            uint x)
        {
            return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
        }

        private static uint Theta1(
            uint x)
        {
            return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
        }

        /* SHA-256 Constants
        * (represent the first 32 bits of the fractional parts of the
        * cube roots of the first sixty-four prime numbers)
        */
        private static readonly uint[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        public override IMemoable Copy()
        {
            return new Sha256Digest(this);
        }

        public override void Reset(IMemoable other)
        {
            Sha256Digest d = (Sha256Digest)other;

            CopyIn(d);
        }
    }

        internal sealed class Pack
    {
        private Pack()
        {
        }

        internal static void UInt16_To_BE(ushort n, byte[] bs)
        {
            bs[0] = (byte)(n >> 8);
            bs[1] = (byte)(n);
        }

        internal static void UInt16_To_BE(ushort n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 8);
            bs[off + 1] = (byte)(n);
        }

        internal static ushort BE_To_UInt16(byte[] bs)
        {
            uint n = (uint)bs[0] << 8
                | (uint)bs[1];
            return (ushort)n;
        }

        internal static ushort BE_To_UInt16(byte[] bs, int off)
        {
            uint n = (uint)bs[off] << 8
                | (uint)bs[off + 1];
            return (ushort)n;
        }

        internal static byte[] UInt32_To_BE(uint n)
        {
            byte[] bs = new byte[4];
            UInt32_To_BE(n, bs, 0);
            return bs;
        }

        internal static void UInt32_To_BE(uint n, byte[] bs)
        {
            bs[0] = (byte)(n >> 24);
            bs[1] = (byte)(n >> 16);
            bs[2] = (byte)(n >> 8);
            bs[3] = (byte)(n);
        }

        internal static void UInt32_To_BE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)(n);
        }

        internal static byte[] UInt32_To_BE(uint[] ns)
        {
            byte[] bs = new byte[4 * ns.Length];
            UInt32_To_BE(ns, bs, 0);
            return bs;
        }

        internal static void UInt32_To_BE(uint[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt32_To_BE(ns[i], bs, off);
                off += 4;
            }
        }

        internal static uint BE_To_UInt32(byte[] bs)
        {
            return (uint)bs[0] << 24
                | (uint)bs[1] << 16
                | (uint)bs[2] << 8
                | (uint)bs[3];
        }

        internal static uint BE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off] << 24
                | (uint)bs[off + 1] << 16
                | (uint)bs[off + 2] << 8
                | (uint)bs[off + 3];
        }

        internal static void BE_To_UInt32(byte[] bs, int off, uint[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = BE_To_UInt32(bs, off);
                off += 4;
            }
        }

        internal static byte[] UInt64_To_BE(ulong n)
        {
            byte[] bs = new byte[8];
            UInt64_To_BE(n, bs, 0);
            return bs;
        }

        internal static void UInt64_To_BE(ulong n, byte[] bs)
        {
            UInt32_To_BE((uint)(n >> 32), bs);
            UInt32_To_BE((uint)(n), bs, 4);
        }

        internal static void UInt64_To_BE(ulong n, byte[] bs, int off)
        {
            UInt32_To_BE((uint)(n >> 32), bs, off);
            UInt32_To_BE((uint)(n), bs, off + 4);
        }

        internal static byte[] UInt64_To_BE(ulong[] ns)
        {
            byte[] bs = new byte[8 * ns.Length];
            UInt64_To_BE(ns, bs, 0);
            return bs;
        }

        internal static void UInt64_To_BE(ulong[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt64_To_BE(ns[i], bs, off);
                off += 8;
            }
        }

        internal static ulong BE_To_UInt64(byte[] bs)
        {
            uint hi = BE_To_UInt32(bs);
            uint lo = BE_To_UInt32(bs, 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        internal static ulong BE_To_UInt64(byte[] bs, int off)
        {
            uint hi = BE_To_UInt32(bs, off);
            uint lo = BE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        internal static void BE_To_UInt64(byte[] bs, int off, ulong[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = BE_To_UInt64(bs, off);
                off += 8;
            }
        }

        internal static void UInt16_To_LE(ushort n, byte[] bs)
        {
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
        }

        internal static void UInt16_To_LE(ushort n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
        }

        internal static ushort LE_To_UInt16(byte[] bs)
        {
            uint n = (uint)bs[0]
                | (uint)bs[1] << 8;
            return (ushort)n;
        }

        internal static ushort LE_To_UInt16(byte[] bs, int off)
        {
            uint n = (uint)bs[off]
                | (uint)bs[off + 1] << 8;
            return (ushort)n;
        }

        internal static byte[] UInt32_To_LE(uint n)
        {
            byte[] bs = new byte[4];
            UInt32_To_LE(n, bs, 0);
            return bs;
        }

        internal static void UInt32_To_LE(uint n, byte[] bs)
        {
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
            bs[2] = (byte)(n >> 16);
            bs[3] = (byte)(n >> 24);
        }

        internal static void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        internal static byte[] UInt32_To_LE(uint[] ns)
        {
            byte[] bs = new byte[4 * ns.Length];
            UInt32_To_LE(ns, bs, 0);
            return bs;
        }

        internal static void UInt32_To_LE(uint[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt32_To_LE(ns[i], bs, off);
                off += 4;
            }
        }

        internal static uint LE_To_UInt32(byte[] bs)
        {
            return (uint)bs[0]
                | (uint)bs[1] << 8
                | (uint)bs[2] << 16
                | (uint)bs[3] << 24;
        }

        internal static uint LE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off]
                | (uint)bs[off + 1] << 8
                | (uint)bs[off + 2] << 16
                | (uint)bs[off + 3] << 24;
        }

        internal static void LE_To_UInt32(byte[] bs, int off, uint[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LE_To_UInt32(bs, off);
                off += 4;
            }
        }

        internal static void LE_To_UInt32(byte[] bs, int bOff, uint[] ns, int nOff, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                ns[nOff + i] = LE_To_UInt32(bs, bOff);
                bOff += 4;
            }
        }

        internal static uint[] LE_To_UInt32(byte[] bs, int off, int count)
        {
            uint[] ns = new uint[count];
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LE_To_UInt32(bs, off);
                off += 4;
            }
            return ns;
        }

        internal static byte[] UInt64_To_LE(ulong n)
        {
            byte[] bs = new byte[8];
            UInt64_To_LE(n, bs, 0);
            return bs;
        }

        internal static void UInt64_To_LE(ulong n, byte[] bs)
        {
            UInt32_To_LE((uint)(n), bs);
            UInt32_To_LE((uint)(n >> 32), bs, 4);
        }

        internal static void UInt64_To_LE(ulong n, byte[] bs, int off)
        {
            UInt32_To_LE((uint)(n), bs, off);
            UInt32_To_LE((uint)(n >> 32), bs, off + 4);
        }

        internal static byte[] UInt64_To_LE(ulong[] ns)
        {
            byte[] bs = new byte[8 * ns.Length];
            UInt64_To_LE(ns, bs, 0);
            return bs;
        }

        internal static void UInt64_To_LE(ulong[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt64_To_LE(ns[i], bs, off);
                off += 8;
            }
        }

        internal static void UInt64_To_LE(ulong[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                UInt64_To_LE(ns[nsOff + i], bs, bsOff);
                bsOff += 8;
            }
        }

        internal static ulong LE_To_UInt64(byte[] bs)
        {
            uint lo = LE_To_UInt32(bs);
            uint hi = LE_To_UInt32(bs, 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        internal static ulong LE_To_UInt64(byte[] bs, int off)
        {
            uint lo = LE_To_UInt32(bs, off);
            uint hi = LE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        internal static void LE_To_UInt64(byte[] bs, int off, ulong[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LE_To_UInt64(bs, off);
                off += 8;
            }
        }

        internal static void LE_To_UInt64(byte[] bs, int bsOff, ulong[] ns, int nsOff, int nsLen)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                ns[nsOff + i] = LE_To_UInt64(bs, bsOff);
                bsOff += 8;
            }
        }
    }

    /**
    * base implementation of MD4 family style digest as outlined in
    * "Handbook of Applied Cryptography", pages 344 - 347.
    */
    public abstract class GeneralDigest
        : IDigest, IMemoable
    {
        private const int BYTE_LENGTH = 64;

        private byte[] xBuf;
        private int xBufOff;

        private long byteCount;

        internal GeneralDigest()
        {
            xBuf = new byte[4];
        }

        internal GeneralDigest(GeneralDigest t)
        {
            xBuf = new byte[t.xBuf.Length];
            CopyIn(t);
        }

        protected void CopyIn(GeneralDigest t)
        {
            Array.Copy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

            xBufOff = t.xBufOff;
            byteCount = t.byteCount;
        }

        public void Update(byte input)
        {
            xBuf[xBufOff++] = input;

            if (xBufOff == xBuf.Length)
            {
                ProcessWord(xBuf, 0);
                xBufOff = 0;
            }

            byteCount++;
        }

        public void BlockUpdate(
            byte[] input,
            int inOff,
            int length)
        {
            length = System.Math.Max(0, length);

            //
            // fill the current word
            //
            int i = 0;
            if (xBufOff != 0)
            {
                while (i < length)
                {
                    xBuf[xBufOff++] = input[inOff + i++];
                    if (xBufOff == 4)
                    {
                        ProcessWord(xBuf, 0);
                        xBufOff = 0;
                        break;
                    }
                }
            }

            //
            // process whole words.
            //
            int limit = ((length - i) & ~3) + i;
            for (; i < limit; i += 4)
            {
                ProcessWord(input, inOff + i);
            }

            //
            // load in the remainder.
            //
            while (i < length)
            {
                xBuf[xBufOff++] = input[inOff + i++];
            }

            byteCount += length;
        }

        public void Finish()
        {
            long bitLength = (byteCount << 3);

            //
            // add the pad bytes.
            //
            Update((byte)128);

            while (xBufOff != 0) Update((byte)0);
            ProcessLength(bitLength);
            ProcessBlock();
        }

        public virtual void Reset()
        {
            byteCount = 0;
            xBufOff = 0;
            Array.Clear(xBuf, 0, xBuf.Length);
        }

        public int GetByteLength()
        {
            return BYTE_LENGTH;
        }

        internal abstract void ProcessWord(byte[] input, int inOff);
        internal abstract void ProcessLength(long bitLength);
        internal abstract void ProcessBlock();
        public abstract string AlgorithmName { get; }
        public abstract int GetDigestSize();
        public abstract int DoFinal(byte[] output, int outOff);
        public abstract IMemoable Copy();
        public abstract void Reset(IMemoable t);
    }

    public interface IMemoable
    {
        /// <summary>
        /// Produce a copy of this object with its configuration and in its current state.
        /// </summary>
        /// <remarks>
        /// The returned object may be used simply to store the state, or may be used as a similar object
        /// starting from the copied state.
        /// </remarks>
        IMemoable Copy();

        /// <summary>
        /// Restore a copied object state into this object.
        /// </summary>
        /// <remarks>
        /// Implementations of this method <em>should</em> try to avoid or minimise memory allocation to perform the reset.
        /// </remarks>
        /// <param name="other">an object originally {@link #copy() copied} from an object of the same type as this instance.</param>
        /// <exception cref="InvalidCastException">if the provided object is not of the correct type.</exception>
        /// <exception cref="MemoableResetException">if the <b>other</b> parameter is in some other way invalid.</exception>
        void Reset(IMemoable other);
    }
}
