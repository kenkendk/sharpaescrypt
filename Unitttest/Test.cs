using NUnit.Framework;
using System;
using System.IO;
using SharpAESCrypt;

namespace Unitttest
{
	[TestFixture()]
	public class Test
	{
		const int MIN_SIZE = 1024 * 5;
		const int MAX_SIZE = 1024 * 1024 * 100; //100mb
		const int REPETIONS = 1000;

		[Test()]
		public void TestVersions()
		{
			var rnd = new Random();
			var failed = 0;

			//Test each supported version
			for (byte v = 0; v <= SharpAESCrypt.SharpAESCrypt.MAX_FILE_VERSION; v++)
			{
				SharpAESCrypt.SharpAESCrypt.DefaultFileVersion = v;
				// Test at boundaries and around the block/keysize margins
				foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
					for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.SharpAESCrypt.BLOCK_SIZE + 1); i++)
						using (MemoryStream ms = new MemoryStream())
						{
							byte[] tmp = new byte[i];
							rnd.NextBytes(tmp);
							ms.Write(tmp, 0, tmp.Length);
							if (!Unittest(string.Format("Testing version {0} with length = {1} => ", v, ms.Length), ms, -1, false))
								failed++;
						}
			}

			if (failed != 0)
				throw new Exception(string.Format("Failed with {0} tests", failed));
		}

		[Test()]
		public void TestNonSeekable()
		{
			var rnd = new Random();
			var failed = 0;

			//Test each supported version with variable buffer lengths
			// Version 0 does not support this
			for (byte v = 1; v <= SharpAESCrypt.SharpAESCrypt.MAX_FILE_VERSION; v++)
			{
				SharpAESCrypt.SharpAESCrypt.DefaultFileVersion = v;
				// Test at boundaries and around the block/keysize margins
				foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
					for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.SharpAESCrypt.BLOCK_SIZE + 1); i++)
						using (var ms = new MemoryStream())
						{
							byte[] tmp = new byte[i];
							rnd.NextBytes(tmp);
							ms.Write(tmp, 0, tmp.Length);
							if (!Unittest(string.Format("Testing non-seekable version {0} with length = {1}, variable buffer sizes => ", v, ms.Length), ms, i + 3, true))
								failed++;
						}
			}

			if (failed != 0)
				throw new Exception(string.Format("Failed with {0} tests", failed));

		}

		[Test()]
		public void TestVariableLengths()
		{
			var rnd = new Random();
			var failed = 0;

			//Test each supported version with variable buffer lengths
			for (byte v = 0; v <= SharpAESCrypt.SharpAESCrypt.MAX_FILE_VERSION; v++)
			{
				SharpAESCrypt.SharpAESCrypt.DefaultFileVersion = v;
				// Test at boundaries and around the block/keysize margins
				foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
					for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.SharpAESCrypt.BLOCK_SIZE + 1); i++)
						using (MemoryStream ms = new MemoryStream())
						{
							byte[] tmp = new byte[i];
							rnd.NextBytes(tmp);
							ms.Write(tmp, 0, tmp.Length);
							if (!Unittest(string.Format("Testing version {0} with length = {1}, variable buffer sizes => ", v, ms.Length), ms, i + 3, false))
								failed++;
						}
			}

			if (failed != 0)
				throw new Exception(string.Format("Failed with {0} tests", failed));
		}

		[Test()]
		public void TestBulkRuns()
		{
			var rnd = new Random();
			var failed = 0;

			SharpAESCrypt.SharpAESCrypt.DefaultFileVersion = SharpAESCrypt.SharpAESCrypt.MAX_FILE_VERSION;

			for (int i = 0; i < REPETIONS; i++)
			{
				using (MemoryStream ms = new MemoryStream())
				{
					byte[] tmp = new byte[rnd.Next(MIN_SIZE, MAX_SIZE)];
					rnd.NextBytes(tmp);
					ms.Write(tmp, 0, tmp.Length);
					if (!Unittest(string.Format("Testing bulk {0} of {1} with length = {2} => ", i, REPETIONS, ms.Length), ms, 4096, false))
						failed++;
				}
			}

			if (failed != 0)
				throw new Exception(string.Format("Failed with {0} tests", failed));
		}
		/// <summary>
		/// Helper function to perform a single test.
		/// </summary>
		/// <param name="message">A message printed to the console</param>
		/// <param name="input">The stream to test with</param>
		private static bool Unittest(string message, MemoryStream input, int useRndBufSize, bool useNonSeekable)
		{
			Console.Write(message);

			const string PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#¤%&/()=?`*'^¨-_.:,;<>|";
			const int MIN_LEN = 1;
			const int MAX_LEN = 25;

			try
			{
				var rnd = new Random();
				var pwdchars = new char[rnd.Next(MIN_LEN, MAX_LEN)];
				for (int i = 0; i < pwdchars.Length; i++)
					pwdchars[i] = PASSWORD_CHARS[rnd.Next(0, PASSWORD_CHARS.Length)];

				input.Position = 0;

				using (var enc = new MemoryStream())
				using (var dec = new MemoryStream())
				using (var nenc = useNonSeekable ? (Stream)new NonSeekableStream(enc) : (Stream)enc)
				using (var ndec = useNonSeekable ? (Stream)new NonSeekableStream(dec) : (Stream)dec)
				{
					SharpAESCrypt.SharpAESCrypt.Encrypt(new string(pwdchars), input, nenc);
					enc.Position = 0;
					if (useRndBufSize <= 0)
						SharpAESCrypt.SharpAESCrypt.Decrypt(new string(pwdchars), nenc, dec);
					else
						UnitStreamDecrypt(new string(pwdchars), nenc, dec, useRndBufSize);

					dec.Position = 0;
					input.Position = 0;

					if (dec.Length != input.Length)
						throw new Exception(string.Format("Length differ {0} vs {1}", dec.Length, input.Length));

					for (int i = 0; i < dec.Length; i++)
						if (dec.ReadByte() != input.ReadByte())
							throw new Exception(string.Format("Streams differ at byte {0}", i));
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine("FAILED: " + ex.Message);
				return false;
			}

			Console.WriteLine("OK!");
			return true;
		}



		/// <summary>
		/// For Unit testing: Decrypt a stream using the supplied password with changing (small) buffer sizes
		/// </summary>
		/// <param name="password">The password to decrypt with</param>
		/// <param name="input">The input stream</param>
		/// <param name="output">The output stream</param>
		private static void UnitStreamDecrypt(string password, Stream input, Stream output, int bufferSizeSelect)
		{
			var r = new Random();

			var partBufs = Math.Min(bufferSizeSelect, 1024);

			var buffers = new byte[partBufs][];
			for (int bs = 1; bs < partBufs; bs++)
				buffers[bs] = new byte[bs];

			buffers[0] = new byte[bufferSizeSelect];

			int a;
			var c = new SharpAESCrypt.SharpAESCrypt(password, input, OperationMode.Decrypt);
			do
			{
				var bufLen = r.Next(bufferSizeSelect) + 1;
				var useBuf = bufLen < partBufs ? buffers[bufLen] : buffers[0];
				a = c.Read(useBuf, 0, bufLen);
				output.Write(useBuf, 0, a);
			} while (a != 0);
		}
	}
}

