using org.BouncyCastle.Math

namespace makwa
{
	public class MakwaPrivateKey
	{

		private BigInteger p;
		private BigInteger q;
		private BigInteger modulus;
		private BigInteger invQ;

		public MakwaPrivateKey(sbyte[] encoded)
		{
			try
			{
				System.IO.Stream input = new System.IO.MemoryStream(encoded);
				int magic = MakwaIO.read32(input);
				if (magic != MakwaIO.MAGIC_PRIVKEY)
				{
					throw new MakwaException("not an encoded Makwa private key");
				}
				System.Numerics.BigInteger p = MakwaIO.readMPI(input);
				System.Numerics.BigInteger q = MakwaIO.readMPI(input);
				if (input.Read() >= 0)
				{
					throw new MakwaException("invalid Makwa" + " private key (trailing garbage)");
				}
				init(p, q);
			}
			catch (IOException)
			{
				throw new MakwaException("invalid Makwa private key (truncated)");
			}
		}

		/// <summary>
		/// Create a new instance with two specific primes. This method
		/// makes some sanity checks but does not verify that the two
		/// prime integers are indeed prime.
		/// </summary>
		/// <param name="p">   the first prime factor </param>
		/// <param name="q">   the second prime factor </param>
		public MakwaPrivateKey(System.Numerics.BigInteger p, System.Numerics.BigInteger q)
		{
			init(p, q);
		}

		private void init(System.Numerics.BigInteger p, System.Numerics.BigInteger q)
		{
			if (p.signum() <= 0 || q.signum() <= 0 || (p.intValue() & 3) != 3 || (q.intValue() & 3) != 3 || p.Equals(q))
			{
				throw new MakwaException("invalid Makwa private key");
			}
			if (p.compareTo(q) < 0)
			{
				// We normally want the first prime to be the
				// largest of the two. This can help some
				// implementations of the CRT.
				System.Numerics.BigInteger t = p;
				p = q;
				q = t;
			}
			this.p = p;
			this.q = q;
			modulus = p * q;
			if (modulus.bitLength() < 1273)
			{
				throw new MakwaException("invalid Makwa private key");
			}
			try
			{
				invQ = q.modInverse(p);
			}
			catch (ArithmeticException ae)
			{
				// This cannot happen if p and q are distinct
				// and both prime, as they should.
				throw new MakwaException(ae);
			}
		}

		/// <summary>
		/// Get the modulus (public key).
		/// </summary>
		/// <returns>  the Makwa modulus </returns>
		public virtual System.Numerics.BigInteger Modulus
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
		/// <exception cref="MakwaException">  on error </exception>
		public static MakwaPrivateKey generate(int size)
		{
			if (size < 1273 || size > 32768)
			{
				throw new MakwaException("invalid modulus size: " + size);
			}
			int sizeP = (size + 1) >> 1;
			int sizeQ = size - sizeP;
			System.Numerics.BigInteger p = makeRandPrime(sizeP);
			System.Numerics.BigInteger q = makeRandPrime(sizeQ);
			MakwaPrivateKey k = new MakwaPrivateKey(p, q);
			if (k.Modulus.bitLength() != size)
			{
				throw new MakwaException("key generation error");
			}
			return k;
		}

		/// <summary>
		/// Encode the private key into bytes.
		/// </summary>
		/// <returns>  the encoded private key </returns>
		public virtual sbyte[] exportPrivate()
		{
			try
			{
				System.IO.MemoryStream @out = new System.IO.MemoryStream();
				MakwaIO.write32(@out, MakwaIO.MAGIC_PRIVKEY);
				MakwaIO.writeMPI(@out, p);
				MakwaIO.writeMPI(@out, q);
				return @out.toByteArray();
			}
			catch (IOException ioe)
			{
				// Cannot actually happen.
				throw new MakwaException(ioe);
			}
		}

		/// <summary>
		/// Encode the public key (modulus) into bytes.
		/// </summary>
		/// <returns>  the encoded modulus </returns>
		public virtual sbyte[] exportPublic()
		{
			return encodePublic(modulus);
		}

		/// <summary>
		/// Encode a modulus into bytes.
		/// </summary>
		/// <param name="modulus">   the modulus </param>
		/// <returns>  the encoded modulus </returns>
		public static sbyte[] encodePublic(System.Numerics.BigInteger modulus)
		{
			try
			{
				System.IO.MemoryStream @out = new System.IO.MemoryStream();
				MakwaIO.write32(@out, MakwaIO.MAGIC_PUBKEY);
				MakwaIO.writeMPI(@out, modulus);
				return @out.toByteArray();
			}
			catch (IOException ioe)
			{
				// Cannot actually happen.
				throw new MakwaException(ioe);
			}
		}

		/// <summary>
		/// Decode a modulus from its encoded representation.
		/// </summary>
		/// <param name="encoded">   the encoded modulus </param>
		/// <returns>  the modulus </returns>
		/// <exception cref="MakwaException">  on error </exception>
		public static System.Numerics.BigInteger decodePublic(sbyte[] encoded)
		{
			try
			{
				System.IO.Stream input = new System.IO.MemoryStream(encoded);
				int magic = MakwaIO.read32(input);
				if (magic != MakwaIO.MAGIC_PUBKEY)
				{
					throw new MakwaException("not an encoded Makwa modulus");
				}
				System.Numerics.BigInteger mod = MakwaIO.readMPI(input);
				if (input.Read() >= 0)
				{
					throw new MakwaException("invalid Makwa" + " modulus (trailing garbage)");
				}
				return mod;
			}
			catch (IOException)
			{
				throw new MakwaException("invalid Makwa private key (truncated)");
			}
		}

		internal virtual System.Numerics.BigInteger P
		{
			get
			{
				return p;
			}
		}

		internal virtual System.Numerics.BigInteger Q
		{
			get
			{
				return q;
			}
		}

		internal virtual System.Numerics.BigInteger InvQ
		{
			get
			{
				return invQ;
			}
		}


private static SecureRandom RNG;

	internal static void prng(sbyte[] buf)
	{
		lock (typeof(<missing class>))
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
	internal static BigInteger makeRandInt(BigInteger m)
	{
		if (m.signum() <= 0)
		{
			throw new MakwaException("invalid modulus (negative)");
		}
		if (m.Equals(System.Numerics.BigInteger.One))
		{
			return System.Numerics.BigInteger.Zero;
		}
		int blen = m.bitLength();
		int len = (int)((uint)(blen + 7) >> 3);
		int mask = (int)((uint)0xFF >> (8 * len - blen));
		sbyte[] buf = new sbyte[len];
		for (;;)
		{
			prng(buf);
			buf[0] &= (sbyte)mask;
			BigInteger z = new BigInteger(1, buf);
			if (z.compareTo(m) < 0)
			{
				return z;
			}
		}
	}

	/*
	 * Make a random integer in the 1..m-1 range (inclusive).
	 */
	internal static BigInteger makeRandNonZero(BigInteger m)
	{
		if (m.compareTo(System.Numerics.BigInteger.One) <= 0)
		{
			throw new MakwaException("invalid modulus (less than 2)");
		}
		for (;;)
		{
			BigInteger z = makeRandInt(m);
			if (z.signum() != 0)
			{
				return z;
			}
		}
	}

	/*
	 * Product of all primes from 3 to 47.
	 */
	private const long PSP = 307444891294245705L;
	private static readonly BigInteger PSPB = BigInteger.valueOf(PSP);

	/*
	 * Returns true if the provided integer is a multiple of a prime
	 * integer in the 2 to 47 range. Note that it returns true if
	 * x is equal to one of these small primes.
	 */
	private static bool isMultipleSmallPrime(BigInteger x)
	{
		if (x.signum() < 0)
		{
			x = x.negate();
		}
		if (x.signum() == 0)
		{
			return true;
		}
		if (!x.testBit(0))
		{
			return true;
		}
		long a = PSP;
		long b = x.mod(PSPB).longValue();
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
	private static bool passesMR(BigInteger n, int cc)
	{
		/*
		 * Normalize n and handle very small values and even
		 * integers.
		 */
		if (n.signum() < 0)
		{
			n = n.negate();
		}
		if (n.signum() == 0)
		{
			return true;
		}
		if (n.bitLength() <= 3)
		{
			switch (n.intValue())
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
		if (!n.testBit(0))
		{
			return true;
		}

		/*
		 * Miller-Rabin algorithm:
		 *
		 * Set n-1 = r * 2^s  for an odd integer r and an integer s.
		 * For each round:
		 *  1. Choose a random a in the 2..n-2 range (inclusive)
		 *  2. Compute y = a^r mod n
		 *  3. If y != 1 and y != n-1, do:
		 *     a. j <- 1
		 *     b. while j < s and y != n-1:
		 *          y <- y^2 mod n
		 *          if y = 1 return false
		 *          j <- j+1
		 *     c. if y != n-1 return false
		 *
		 * If we do all the rounds without detecting a composite,
		 * return true.
		 */
		BigInteger nm1 = n.subtract(System.Numerics.BigInteger.One);
		BigInteger nm2 = nm1.subtract(System.Numerics.BigInteger.One);
		BigInteger r = nm1;
		int s = 0;
		while (!r.testBit(0))
		{
			s++;
			r = r.shiftRight(1);
		}
		while (cc -- > 0)
		{
			BigInteger a = makeRandNonZero(nm2).add(System.Numerics.BigInteger.One);
			BigInteger y = a.modPow(r, n);
			if (!y.Equals(System.Numerics.BigInteger.One) && !y.Equals(nm1))
			{
				for (int j = 1; j < s; j++)
				{
					if (y.Equals(nm1))
					{
						break;
					}
					y = y.multiply(y).mod(n);
					if (y.Equals(System.Numerics.BigInteger.One))
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

	private static int computeNumMR(int k)
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


//====================================================================================================
//End of the allowed output for the Free Edition of Java to C# Converter.

//To purchase the Premium Edition, visit our website:
//https://www.tangiblesoftwaresolutions.com/order/order-java-to-csharp.html
//====================================================================================================
