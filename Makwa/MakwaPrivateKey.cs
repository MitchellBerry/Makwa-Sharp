﻿using System;
using System.IO;
using Makwa.BigInt;

namespace Makwa
{
    public class MakwaPrivateKey
    {
        public BigInteger p;
        public BigInteger q;
        private BigInteger modulus;
        private BigInteger invQ;

        public MakwaPrivateKey(byte[] encoded)
        {
            try
            {
                Stream input = new MemoryStream(encoded);
                int magic = IO.Read32(input);
                if (magic != IO.MAGIC_PRIVKEY)
                {
                    throw new Exception("not an encoded Makwa private key");
                }
                BigInteger p = IO.ReadMPI(input);
                BigInteger q = IO.ReadMPI(input);
                long len = input.Length;
                byte[] arr = new byte[len];

                if (input.Read(arr, 0, (int)len) >= 0)
                {
                    throw new Exception("invalid Makwa" + " private key (trailing garbage)");
                }
                Init(p, q);
            }
            catch (IOException)
            {
                throw new Exception("invalid Makwa private key (truncated)");
            }
        }

        /// <summary>
        /// Create a new instance with two specific primes. This method
        /// makes some sanity checks but does not verify that the two
        /// prime integers are indeed prime.
        /// </summary>
        /// <param name="p">   the first prime factor </param>
        /// <param name="q">   the second prime factor </param>
        public MakwaPrivateKey(BigInteger p, BigInteger q)
        {
            Init(p, q);
        }

        private void Init(BigInteger p, BigInteger q)
        {
            if (p.SignValue <= 0 || q.SignValue <= 0 || (p.IntValue & 3) != 3 || (q.IntValue & 3) != 3 || p.Equals(q))
            {
                throw new Exception("invalid Makwa private key");
            }
            if (p.CompareTo(q) < 0)
            {
                BigInteger t = p;
                p = q;
                q = t;
            }
            this.p = p;
            this.q = q;
            modulus = p.Multiply(q);
            if (modulus.BitLength < 1273)
            {
                throw new Exception("invalid Makwa private key");
            }
            try
            {
                invQ = q.ModInverse(p);
            }
            catch (ArithmeticException ae)
            {
                throw new Exception(ae.ToString());
            }
        }

        /// <summary>
        /// Get the modulus (public key).
        /// </summary>
        /// <returns>  The Makwa modulus </returns>
        public virtual BigInteger Modulus
        {
            get
            {
                return modulus;
            }
        }

        /// <summary>
        /// Generate a new private key. A secure PRNG is used to produce
        /// the new private key. The target modulus size (in bits) is
        /// provided as parameter; it must be no smaller than 1273 bits,
        /// and no greater than 32768 bits. The normal and recommended
        /// modulus size is 2048 bits.
        /// </summary>
        /// <param name="size">   the target modulus size </param>
        /// <returns>  the new private key </returns>
        /// <exception cref="Exception">  on error </exception>
        public static MakwaPrivateKey Generate(int size)
        {
            if (size < 1273 || size > 32768)
            {
                throw new Exception("invalid modulus size: " + size);
            }
            int sizeP = (size + 1) >> 1;
            int sizeQ = size - sizeP;
            BigInteger p = MakeRandPrime(sizeP);
            BigInteger q = MakeRandPrime(sizeQ);
            MakwaPrivateKey k = new MakwaPrivateKey(p, q);
            if (k.Modulus.BitLength != size)
            {
                throw new Exception("key generation error");
            }
            return k;
        }

        internal virtual BigInteger P
        {
            get
            {
                return p;
            }
        }

        internal virtual BigInteger Q
        {
            get
            {
                return q;
            }
        }

        internal virtual BigInteger InvQ
        {
            get
            {
                return invQ;
            }
        }


        private static SecureRandom RNG;

        internal static void Prng(byte[] buf)
        {

            {
                if (RNG == null)
                {
                    RNG = new SecureRandom();
                }
                RNG.NextBytes(buf);
            }
        }

        /*
         * Generate a random integer in the 0..m-1 range (inclusive).
         */
        internal static BigInteger MakeRandInt(BigInteger m)
        {
            if (m.SignValue <= 0)
            {
                throw new Exception("invalid modulus (negative)");
            }
            if (m.Equals(BigInteger.One))
            {
                return BigInteger.Zero;
            }
            int blen = m.BitLength;
            int len = (int)((uint)(blen + 7) >> 3);
            int mask = (int)((uint)0xFF >> (8 * len - blen));
            byte[] buf = new byte[len];
            for (; ; )
            {
                Prng(buf);
                buf[0] &= (byte)mask;
                BigInteger z = new BigInteger(1, buf);
                if (z.CompareTo(m) < 0)
                {
                    return z;
                }
            }
        }

        /*
         * Make a random integer in the 1..m-1 range (inclusive).
         */
        internal static BigInteger MakeRandNonZero(BigInteger m)
        {
            if (m.CompareTo(BigInteger.One) <= 0)
            {
                throw new Exception("invalid modulus (less than 2)");
            }
            for (; ; )
            {
                BigInteger z = MakeRandInt(m);
                if (z.SignValue != 0)
                {
                    return z;
                }
            }
        }

        /*
         * Product of all primes from 3 to 47.
         */
        private const long PSP = 307444891294245705L;
        private static readonly BigInteger PSPB = BigInteger.ValueOf(PSP);

        /*
         * Returns true if the provided integer is a multiple of a prime
         * integer in the 2 to 47 range. Note that it returns true if
         * x is equal to one of these small primes.
         */
        private static bool IsMultipleSmallPrime(BigInteger x)
        {
            if (x.SignValue < 0)
            {
                x = x.Negate();
            }
            if (x.SignValue == 0)
            {
                return true;
            }
            if (!x.TestBit(0))
            {
                return true;
            }
            long a = PSP;
            long b = x.Mod(PSPB).LongValue;
            while (b != 0)
            {
                long t = a % b;
                a = b;
                b = t;
            }
            return a != 1;
        }

        /// <summary>
        /// Test n for non-primality with some rounds of Miller-Rabin.
        /// Returned value is false if n is composite, true if n was
        /// not detected as composite.
        /// 
        /// Number of rounds should be adjusted so that the probability
        /// of a composite integer not to be detected is sufficiently
        /// low. IF the candidate value is a random odd integer (as is
        /// the case here, and as opposed to a potentially specially
        /// crafted integer), then the number of rounds can be quite low.
        /// The Handbook of Applied Cryptography, section 4.4.1,
        /// discusses these issues; in particular, for RANDOM odd
        /// integers of at least 300 bits, 9 rounds are sufficient to
        /// get probability of failure below 2^-80.
        /// </summary>
        /// <param name="n">    the integer to test </param>
        /// <param name="cc">   the count of rounds </param>
        /// <returns>  {@code false} for a composite integer, {@code true}
        ///          if the value was not detected as composite </returns>
        private static bool PassesMR(BigInteger n, int cc)
        {

            if (n.SignValue < 0)
            {
                n = n.Negate();
            }
            if (n.SignValue == 0)
            {
                return true;
            }
            if (n.BitLength <= 3)
            {
                switch (n.IntValue)
                {
                    case 2:
                    case 3:
                    case 5:
                    case 7:
                        return false;
                    default:
                        return true;
                }
            }
            if (!n.TestBit(0))
            {
                return true;
            }

            BigInteger nm1 = n.Subtract(BigInteger.One);
            BigInteger nm2 = nm1.Subtract(BigInteger.One);
            BigInteger r = nm1;
            int s = 0;
            while (!r.TestBit(0))
            {
                s++;
                r = r.ShiftRight(1);
            }
            while (cc-- > 0)
            {
                BigInteger a = MakeRandNonZero(nm2).Add(BigInteger.One);
                BigInteger y = a.ModPow(r, n);
                if (!y.Equals(BigInteger.One) && !y.Equals(nm1))
                {
                    for (int j = 1; j < s; j++)
                    {
                        if (y.Equals(nm1))
                        {
                            break;
                        }
                        y = y.Multiply(y).Mod(n);
                        if (y.Equals(BigInteger.One))
                        {
                            return false;
                        }
                    }
                    if (!y.Equals(nm1))
                    {
                        return false;
                    }
                }
            }
            return true;
        }


        /// <summary>
        /// Create a random prime of the provided length (in bits). The
        /// prime size must be at least 8 bits. Moreover, the two top
        /// bits of the resulting prime are forced to 1; this allows to
        /// target a specific modulus size (the product of two 512-bit
        /// primes with the two top bits set is necessarily a 1024-bit
        /// integer, not 1023). Moreover, the prime is guaranteed to be
        /// equal to 3 modulo 4.
        /// </summary>
        /// <param name="size">   the target prime size </param>
        /// <returns>  the new random prime </returns>
        static BigInteger MakeRandPrime(int size)
        {
            int len = (int)((uint)(size + 8) >> 3);
            byte[] buf = new byte[len];
            int mz16 = (int)((uint)0xFFFF >> (8 * len - size));
            int mo16 = (int)((uint)0xC000 >> (8 * len - size));
            for (; ; )
            {
                Prng(buf);
                buf[0] &= (byte)((int)((uint)mz16 >> 8));
                buf[1] &= (byte)mz16;
                buf[0] |= (byte)((int)((uint)mo16 >> 8));
                buf[1] |= (byte)mo16;
                buf[len - 1] |= (byte)0x03;
                BigInteger p = new BigInteger(buf);
                if (p.IsProbablePrime(100))
                {
                    return p;
                }
            }
        }

        /// <summary>
        /// Return the number of Miller-Rabin rounds recommended to detect
        /// composite integers of size 'k' bits with a probability of
        /// failure below 2^-80. We follow here the table 4.4 from the
        /// Handbook of Applied Cryptography.
        /// <strong>WARNING:</strong> this value is good only under the
        /// assumption that the input is a random odd integer. If the
        /// input is specially crafted, it may evade detection with higher
        /// probability.
        /// </summary>
        /// <param name="k">   the input integer size </param>
        /// <returns>  the number of Miller-Rabin rounds </returns>
        private static int ComputeNumMR(int k)
        {
            if (k < 400)
            {
                if (k < 250)
                {
                    if (k < 100)
                    {
                        return 40;
                    }
                    else if (k < 150)
                    {
                        return 27;
                    }
                    else if (k < 200)
                    {
                        return 18;
                    }
                    else
                    {
                        return 15;
                    }
                }
                else
                {
                    if (k < 300)
                    {
                        return 12;
                    }
                    else if (k < 350)
                    {
                        return 9;
                    }
                    else
                    {
                        return 8;
                    }
                }
            }
            else
            {
                if (k < 650)
                {
                    if (k < 450)
                    {
                        return 7;
                    }
                    else if (k < 550)
                    {
                        return 6;
                    }
                    else
                    {
                        return 5;
                    }
                }
                else
                {
                    if (k < 850)
                    {
                        return 4;
                    }
                    else if (k < 1300)
                    {
                        return 3;
                    }
                    else
                    {
                        return 2;
                    }
                }
            }
        }
    }
}


