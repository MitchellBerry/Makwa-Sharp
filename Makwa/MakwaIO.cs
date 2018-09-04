using System;
using System.IO;
using Org.BouncyCastle.Math;

namespace makwa
{
	internal sealed class MakwaIO
	{
		internal const int MAGIC_PUBKEY = 0x55414D30;
		internal const int MAGIC_PRIVKEY = 0x55414D31;
		internal const int MAGIC_DELEG_PARAM = 0x55414D32;
		internal const int MAGIC_DELEG_REQ = 0x55414D33;
		internal const int MAGIC_DELEG_ANS = 0x55414D34;

		internal static int read8(Stream input)
		{
            long len = input.Length;
            byte[] arr = new byte[len];
			int x = input.Read(arr, 0, (int)len);
			if (x < 0)
			{
				throw new Exception();
			}
			return x;
		}

		internal static int read16(System.IO.Stream input)
		{
			int h = read8(input);
			int l = read8(input);
			return (h << 8) + l;
		}

		internal static int read32(Stream input)
		{
			int h = read16(input);
			int l = read16(input);
			return (h << 16) + l;
		}

		internal static void readAll(System.IO.Stream input, byte[] buf)
		{
			readAll(input, buf, 0, buf.Length);
		}

		internal static void write8(System.IO.Stream output, int x)
		{
			output.WriteByte((byte)x);
		}

		internal static void write16(System.IO.Stream output, int x)
		{
			output.WriteByte((byte)(x >> 8));
			output.WriteByte((byte)x);
		}

		internal static void write32(System.IO.Stream output, int x)
		{
			output.WriteByte((byte)(x >> 24));
			output.WriteByte((byte)(x >> 16));
			output.WriteByte((byte)(x >> 8));
			output.WriteByte((byte)(x));
		}

		internal static void readAll(System.IO.Stream input, byte[] buf, int off, int len)
		{
			while (len > 0)
			{
				int rlen = input.Read(buf, off, len);
				if (rlen < 0)
				{
					throw new IOException();
				}
				off += rlen;
				len -= rlen;
			}
		}

		internal static void writeMPI(System.IO.Stream output, BigInteger v)
		{
			if (v.SignValue < 0)
			{
				throw new Exception("cannot encode MPI: negative");
			}
			byte[] buf = v.ToByteArray();
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
			output.WriteByte((byte)(len >> 8));
			output.WriteByte((byte)(len & 0xFF));
			output.Write(buf, off, len);
		}

		internal static BigInteger readMPI(System.IO.Stream input)
		{
			int len = read16(input);
			byte[] buf = new byte[len];
			readAll(input, buf);
			return new BigInteger(1, buf);
		}
	}

}