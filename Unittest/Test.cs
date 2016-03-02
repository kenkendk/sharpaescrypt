using NUnit.Framework;
using System;
using System.IO;
using SharpAESCrypt;

using System.Threading.Tasks;
using System.Linq;

namespace SharpAESCrypt.Unittest
{
	[TestFixture()]
	public class Test
	{
		const int MIN_SIZE = 1024 * 5;
		const int MAX_SIZE = 1024 * 1024 * 100; //100mb
		const int REPETIONS = 100; // Travis-CI stops after 120 min. 1000 bulks are too long.

		[Test()]
		public void TestVersions()
		{
			var rnd = new Random();
			var failed = 0;

			//Test each supported version
			for (byte v = 0; v <= SharpAESCrypt.MAX_FILE_VERSION; v++)
			{
				SharpAESCrypt.DefaultFileVersion = v;
				// Test at boundaries and around the block/keysize margins
				foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
					for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.BLOCK_SIZE + 1); i++)
						using (MemoryStream ms = new MemoryStream())
						{
							byte[] tmp = new byte[i];
							rnd.NextBytes(tmp);
							ms.Write(tmp, 0, tmp.Length);
							if (!Unittest(string.Format("Testing version {0} with length = {1} => ", v, ms.Length), ms, -1, false, 1))
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
			for (byte v = 1; v <= SharpAESCrypt.MAX_FILE_VERSION; v++)
			{
				SharpAESCrypt.DefaultFileVersion = v;
				// Test at boundaries and around the block/keysize margins
				foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
					for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.BLOCK_SIZE + 1); i++)
						using (var ms = new MemoryStream())
						{
							byte[] tmp = new byte[i];
							rnd.NextBytes(tmp);
							ms.Write(tmp, 0, tmp.Length);
							if (!Unittest(string.Format("Testing non-seekable version {0} with length = {1}, variable buffer sizes => ", v, ms.Length), ms, i + 3, true, 1))
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
			for (byte v = 0; v <= SharpAESCrypt.MAX_FILE_VERSION; v++)
			{
				SharpAESCrypt.DefaultFileVersion = v;
				// Test at boundaries and around the block/keysize margins
				foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
					for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.BLOCK_SIZE + 1); i++)
						using (MemoryStream ms = new MemoryStream())
						{
							byte[] tmp = new byte[i];
							rnd.NextBytes(tmp);
							ms.Write(tmp, 0, tmp.Length);
							if (!Unittest(string.Format("Testing version {0} with length = {1}, variable buffer sizes => ", v, ms.Length), ms, i + 3, false, 1))
								failed++;
						}
			}

			if (failed != 0)
				throw new Exception(string.Format("Failed with {0} tests", failed));
		}


        /// <summary>
        /// Testing for multithreading uses version 2 and has some special code to detect races
        /// and missing cleanups (threads stalling because sync is missing).
        /// </summary>
        [Test()]
        public void TestMultiThreading()
        {
            var rnd = new Random();
            var failed = 0;
            
            int initialThreadCount = System.Diagnostics.Process.GetCurrentProcess().Threads.Count;

            byte v = SharpAESCrypt.MAX_FILE_VERSION;
            // Test multi-threading modes
            for (int useThreads = 2; useThreads <= 4; useThreads++)
            {
                SharpAESCrypt.DefaultFileVersion = v;
                // Test at boundaries and around the block/keysize margins
                foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
                    for (int i = Math.Max(0, bound - 6 * SharpAESCrypt.BLOCK_SIZE - 1); i <= bound + (6 * SharpAESCrypt.BLOCK_SIZE + 1); i++)
                        using (MemoryStream ms = new MemoryStream())
                        {
                            byte[] tmp = new byte[i];
                            rnd.NextBytes(tmp);
                            ms.Write(tmp, 0, tmp.Length);
                            // Run the test in separate thread to detect races / deadlocks
                            Task<bool> runTest = Task<bool>.Run(() =>
                                Unittest(string.Format("Testing version {0} with length = {1}, using {2} Thread(s) and variable buffer sizes => ",
                                v, ms.Length, useThreads), ms, i + 3, true, useThreads));
                            runTest.Wait(TimeSpan.FromSeconds(300)); // we give a single test a timeout of 5 minutes. This should well be enough!
                            if (!runTest.IsCompleted)
                            {
                                Console.WriteLine("FAILED: Test failed with timeout. There must be a race.");
                                failed++;
                            }
                            else if (!runTest.Result)
                                failed++;
                            // Check for number of threads: a systematic rise would signal that the sync does not work!
                            // We have to allow a lot of threads for the test framework, but it should not go far above 30 normally.
                            int currentThreadCount = System.Diagnostics.Process.GetCurrentProcess().Threads.Count;
                            if (currentThreadCount > initialThreadCount + 50) // too many threads. This shouldn't be!
                                throw new Exception("Allowed thread count threshold reached. Thread synchronization might not work. Also: check test framework!");
                        }
            }

            if (failed != 0)
                throw new Exception(string.Format("Failed with {0} tests", failed));
        }


        /// <summary>
        /// This test checks how decryption reacts to truncated data.
        /// It should always throw with some kind of exception.
        /// Worst cases could be to return any data (also empty) without error.
        /// For multithreading, this could be a special challenge to end all threads and not deadlock.
        /// </summary>
        [Test()]
        public void TestTruncatedDataDecryption()
        {
            var rnd = new Random();
            var failed = 0;

            int initialThreadCount = System.Diagnostics.Process.GetCurrentProcess().Threads.Count;
            int maxByteCount = 1 << 21; // must be larger than maximum test size below. 

            //Test each supported version with variable buffer lengths
            for (byte v = 0; v <= SharpAESCrypt.MAX_FILE_VERSION; v++)
            {
                SharpAESCrypt.DefaultFileVersion = v;

                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] tmp = new byte[maxByteCount];
                    rnd.NextBytes(tmp);
                    string pwd = new string(Enumerable.Repeat('a', 10).Select(c => (char)(c + rnd.Next(26))).ToArray());
                    SharpAESCrypt.Encrypt(pwd, new MemoryStream(tmp), ms, 1);
                    int approxHeaderSize = ((int)ms.Length) - tmp.Length - SharpAESCrypt.HASH_SIZE;

                    // Test at boundaries and around the block/keysize margins
                    int[] bounds = new int[] { 0, 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 };
                    Array.Reverse(bounds);
                    foreach (int bound in bounds)
                    {
                        int low = Math.Max(-approxHeaderSize, bound - 6 * SharpAESCrypt.BLOCK_SIZE - 1);
                        int high = Math.Min((int)ms.Length, bound + (6 * SharpAESCrypt.BLOCK_SIZE + 1));
                        for (int i = approxHeaderSize + high; i >= approxHeaderSize + low; i--)
                        {
                            ms.SetLength(i); // truncate input stream!
                            for (int useThreads = 1; useThreads <= 4; useThreads++)
                            {
                                ms.Position = 0;

                                // Run the test in separate thread to detect races / deadlocks
                                Task<bool> runTest = Task<bool>.Run(() =>
                                    {
                                        Console.Write("Testing version {0} with truncated stream length = {1}, using {2} Thread(s) and variable buffer sizes => ",
                                            v, ms.Length, useThreads);
                                        try
                                        {
                                            UnitStreamDecrypt(pwd, ms, new MemoryStream(tmp), 256, useThreads);
                                            Console.WriteLine("FAILED: Truncated stream accepted."); return false;
                                        }
                                        catch { Console.WriteLine("OK!"); return true; }
                                    });
                                runTest.Wait(TimeSpan.FromSeconds(300)); // we give a single test a timeout of 5 minutes. This should well be enough!
                                if (!runTest.IsCompleted)
                                {
                                    Console.WriteLine("FAILED: A test timed out. There must be a race.");
                                    throw new Exception("A test timed out. There must be a race.");
                                }
                                else if (!runTest.Result)
                                    failed++;
                                // Check for number of threads: a systematic rise would signal that the sync does not work!
                                // We have to allow a lot of threads for the test framework, but it should not go far above 30 normally.
                                int currentThreadCount = System.Diagnostics.Process.GetCurrentProcess().Threads.Count;
                                if (currentThreadCount > initialThreadCount + 50) // too many threads. This shouldn't be!
                                {
                                    Console.WriteLine("FAILED: Allowed thread count threshold reached.");
                                    throw new Exception("Allowed thread count threshold reached. Thread synchronization might not work. Also: check test framework!");
                                }
                            }
                        }
                    }

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

			SharpAESCrypt.DefaultFileVersion = SharpAESCrypt.MAX_FILE_VERSION;

			for (int i = 0; i < REPETIONS; i++)
			{
				using (MemoryStream ms = new MemoryStream())
				{
					byte[] tmp = new byte[rnd.Next(MIN_SIZE, MAX_SIZE)];
					rnd.NextBytes(tmp);
					ms.Write(tmp, 0, tmp.Length);
					int useThreads = (i % 4) + 1;
					if (!Unittest(string.Format("Testing bulk {0} of {1} with length = {2}, using {3} Thread(s) => ", i, REPETIONS, ms.Length, useThreads), ms, 4096, false, useThreads))
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
		private static bool Unittest(string message, MemoryStream input, int useRndBufSize, bool useNonSeekable, int useThreads)
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
					SharpAESCrypt.Encrypt(new string(pwdchars), input, nenc, maxThreads: useThreads);

                    // 1st pass: test with wrong password if version > 0
                    enc.Position = 0;
                    try
                    {
                        if (SharpAESCrypt.DefaultFileVersion > 0)
                        {
                            SharpAESCrypt.Decrypt("!WRONG_PASSWORD!", nenc, dec, maxThreads: useThreads);
                            throw new InvalidOperationException("Wrong password not detected.");
                        }
                    }
                    catch (SharpAESCrypt.WrongPasswordException)
                    { }


                    // 2nd Pass: data ok
                    enc.Position = 0;
					if (useRndBufSize <= 0)
						SharpAESCrypt.Decrypt(new string(pwdchars), nenc, dec, maxThreads: useThreads);
					else
						UnitStreamDecrypt(new string(pwdchars), nenc, dec, useRndBufSize, useThreads);
					dec.Position = 0;
					input.Position = 0;

					if (dec.Length != input.Length)
						throw new Exception(string.Format("Length differ {0} vs {1}", dec.Length, input.Length));

					for (int i = 0; i < dec.Length; i++)
						if (dec.ReadByte() != input.ReadByte())
							throw new Exception(string.Format("Streams differ at byte {0}", i));

                    // 3rd pass: Change hash at end of file, and expect HashMismatch
                    int changeHashAt = rnd.Next(SharpAESCrypt.HASH_SIZE);
                    enc.Position = enc.Length - changeHashAt - 1;
                    int b = enc.ReadByte();
                    enc.Position = enc.Length - changeHashAt - 1;
                    enc.WriteByte((byte)(~b & 0xff));
                    enc.Position = 0;
                    try
                    {
                        if (useRndBufSize <= 0)
                            SharpAESCrypt.Decrypt(new string(pwdchars), nenc, dec, maxThreads: useThreads);
                        else
                            UnitStreamDecrypt(new string(pwdchars), nenc, dec, useRndBufSize, useThreads);
                        throw new InvalidDataException("Mismatching HMAC not detected.");
                    }
                    catch (SharpAESCrypt.HashMismatchException)
                    { }

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
		private static void UnitStreamDecrypt(string password, Stream input, Stream output, int bufferSizeSelect, int useThreads)
		{
			var r = new Random();

			var partBufs = Math.Min(bufferSizeSelect, 1024);

			var buffers = new byte[partBufs][];
			for (int bs = 1; bs < partBufs; bs++)
				buffers[bs] = new byte[bs];

			buffers[0] = new byte[bufferSizeSelect];

			int a;
            var c = new SharpAESCrypt(password, input, OperationMode.Decrypt, true);
			c.MaxCryptoThreads = useThreads;
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
