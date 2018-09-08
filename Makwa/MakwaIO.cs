using System;
using System.IO;
using Makwa.BigInt;

namespace Makwa
{
    public class FileIO
    {
        public static string ModulusFilePath { get; set; } = "modulus";

        public static byte[] GetModulus(string path = null)
        {
            if (path == null) { path = ModulusFilePath; }
            if (File.Exists(path))
            {
                try
                {
                    return File.ReadAllBytes(ModulusFilePath);
                }
                catch (IOException)
                {
                    throw new IOException("Error Reading File: " + ModulusFilePath);
                }
            }
            else
            {
                return CreateNewModulus(path);
            }
        }

        /// <summary>
        ///  Creates a new modulus
        /// </summary>
        /// <param name="path">filepath where modulus is written, default is</param>
        /// <param name="length">modulus length in bits</param>
        /// <returns></returns>
        static byte[] CreateNewModulus(string path, int length = 2048)
        {
            MakwaPrivateKey privateKey = MakwaPrivateKey.Generate(length);
            byte[] modulus = Tools.I2OSP(privateKey.Modulus);
            WriteToFile(path, modulus);
            return modulus;
        }

        /// <summary>
        /// Creates a new private key class, writes modulus and primes p,q to file
        /// </summary>
        /// <param name="path">
        /// filepath, primes are appended with "-p" and "-q" respectively
        /// </param>
        /// <param name="length">modulus length in bits, default is 2048</param>
        /// <returns>MakwaPrivateKey</returns>
        static MakwaPrivateKey CreateNewPrivateKey (string path, int length = 2048)
        {
            MakwaPrivateKey privateKey = MakwaPrivateKey.Generate(length);
            byte[] modulus = Tools.I2OSP(privateKey.Modulus);
            byte[] p = Tools.I2OSP(privateKey.p);
            byte[] q = Tools.I2OSP(privateKey.q);
            WriteToFile(path, modulus);
            WriteToFile(path + "-p", p);
            WriteToFile(path + "-q", q);
            return privateKey;
        }

        /// <summary>
        /// Writes binary key data to file
        /// </summary>
        /// <param name="filepath"></param>
        /// <param name="data"></param>
        static void WriteToFile(string filepath, byte[] data)
        {
            try
            {
                File.WriteAllBytes(filepath, data);
            }
            catch (IOException)
            {
                throw new IOException("Error writing to file: " + 
                    Environment.CurrentDirectory  + "\\" + filepath);
            }
        }

    }
	internal sealed class IO
	{
		internal const int MAGIC_PUBKEY = 0x55414D30;
		internal const int MAGIC_PRIVKEY = 0x55414D31;
		internal const int MAGIC_DELEG_PARAM = 0x55414D32;
		internal const int MAGIC_DELEG_REQ = 0x55414D33;
		internal const int MAGIC_DELEG_ANS = 0x55414D34;

		internal static int Read8(Stream input)
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

		internal static int Read16(Stream input)
		{
			int h = Read8(input);
			int l = Read8(input);
			return (h << 8) + l;
		}

		internal static int Read32(Stream input)
		{
			int h = Read16(input);
			int l = Read16(input);
			return (h << 16) + l;
		}

		internal static void ReadAll(Stream input, byte[] buf)
		{
			ReadAll(input, buf, 0, buf.Length);
		}

		internal static void Write8(Stream output, int x)
		{
			output.WriteByte((byte)x);
		}

		internal static void Write16(Stream output, int x)
		{
			output.WriteByte((byte)(x >> 8));
			output.WriteByte((byte)x);
		}

		internal static void Write32(Stream output, int x)
		{
			output.WriteByte((byte)(x >> 24));
			output.WriteByte((byte)(x >> 16));
			output.WriteByte((byte)(x >> 8));
			output.WriteByte((byte)(x));
		}

		internal static void ReadAll(Stream input, byte[] buf, int off, int len)
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

		internal static void WriteMPI(Stream output, BigInteger v)
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

		internal static BigInteger ReadMPI(Stream input)
		{
			int len = Read16(input);
			byte[] buf = new byte[len];
			ReadAll(input, buf);
			return new BigInteger(1, buf);
		}
	}

}