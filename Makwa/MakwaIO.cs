
namespace makwa
{
	internal sealed class MakwaIO
	{
		internal const int MAGIC_PUBKEY = 0x55414D30;
		internal const int MAGIC_PRIVKEY = 0x55414D31;
		internal const int MAGIC_DELEG_PARAM = 0x55414D32;
		internal const int MAGIC_DELEG_REQ = 0x55414D33;
		internal const int MAGIC_DELEG_ANS = 0x55414D34;

		internal static int read8(System.IO.Stream input)
		{
			int x = input.Read();
			if (x < 0)
			{
				throw new EOFException();
			}
			return x;
		}

		internal static int read16(System.IO.Stream input)
		{
			int h = read8(input);
			int l = read8(input);
			return (h << 8) + l;
		}

		internal static int read32(System.IO.Stream input)
		{
			int h = read16(input);
			int l = read16(input);
			return (h << 16) + l;
		}

		internal static void readAll(System.IO.Stream input, sbyte[] buf)
		{
			readAll(input, buf, 0, buf.Length);
		}

		internal static void write8(System.IO.Stream output, int x)
		{
			output.WriteByte(x);
		}

		internal static void write16(System.IO.Stream output, int x)
		{
			output.WriteByte((int)((uint)x >> 8));
			output.WriteByte(x);
		}

		internal static void write32(System.IO.Stream output, int x)
		{
			output.WriteByte((int)((uint)x >> 24));
			output.WriteByte((int)((uint)x >> 16));
			output.WriteByte((int)((uint)x >> 8));
			output.WriteByte(x);
		}

		internal static void readAll(System.IO.Stream input, sbyte[] buf, int off, int len)
		{
			while (len > 0)
			{
				int rlen = input.Read(buf, off, len);
				if (rlen < 0)
				{
					throw new EOFException();
				}
				off += rlen;
				len -= rlen;
			}
		}

		internal static void writeMPI(System.IO.Stream output, BigInteger v)
		{
			if (v.signum() < 0)
			{
				throw new Exception("cannot encode MPI: negative");
			}
			sbyte[] buf = v.ToByteArray();
			int off;
			if (buf[0] == 0x00 && buf.Length > 1)
			{
				off = 1;
			}
			else
			{
				off = 0;
			}
			int len = buf.Length - off;
			if (len > 0xFFFF)
			{
				throw new Exception("cannot encode MPI: too large");
			}
			output.WriteByte((int)((uint)len >> 8));
			output.WriteByte(len & 0xFF);
			output.Write(buf, off, len);
		}

		internal static BigInteger readMPI(System.IO.Stream input)
		{
			int len = read16(input);
			sbyte[] buf = new sbyte[len];
			readAll(input, buf);
			return new BigInteger(1, buf);
		}
	}

}