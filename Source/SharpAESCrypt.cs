#region Disclaimer / License
// Copyright (C) 2015, Kenneth Skovhede
// http://www.hexad.dk, opensource@hexad.dk
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
// 
#endregion

#region Usage instructions, README
/*************************************************************

 This code is an implementation of the AES Crypt tool:
 http://www.aescrypt.com

 The code is primarily ported using the file format description,
 using the Java code as an example where there were uncertainties.
 It is tested against the AES Crypt binaries, ensuring that the
 binaries and this code are compatible.

 I have NOT tested the version=0 and version=1 formats, they are
 implemented purely by looking at the file format specs.
 If you have test data for these version, please let me know
 if it works.

 Usage:
 There are simple static functions that you can call:
    SharpAESCrypt.Encrypt("password", "inputfile", "outputfile");
    SharpAESCrypt.Decrypt("password", "inputfile", "outputfile");
    SharpAESCrypt.Encrypt("password", inputStream, outputStream);
    SharpAESCrypt.Decrypt("password", inputStream, outputStream);

 You can control what headers are emitted using the static 
 variables:
     SharpAESCrypt.Extension_CreatedByIdentifier
     SharpAESCrypt.Extension_InsertCreateByIdentifier
     SharpAESCrypt.Extension_InsertTimeStamp
     SharpAESCrypt.Extension_InsertPlaceholder
     SharpAESCrypt.DefaultFileVersion 

 If you need more advanced processing, you can initiate an 
 instance and use it as a stream:
    Stream aesStream = new SharpAESCrypt(password, inputStream, mode);

 You can then modify the Version and Extensions properties on
 the instance. If you use the stream mode, make sure you call
 either FlushFinalBlock() or Dispose() when you are done.

 Have fun!

 **************************************************************/
#endregion

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using SharpAESCrypt.Threading;

namespace SharpAESCrypt
{
    /// <summary>
    /// Enumerates the possible modes for encryption and decryption
    /// </summary>
    public enum OperationMode
    {
        /// <summary>
        /// Indicates encryption, which means that the stream must be writeable
        /// </summary>
        Encrypt,
        /// <summary>
        /// Indicates decryption, which means that the stream must be readable
        /// </summary>
        Decrypt
    }

    #region Translateable strings
    /// <summary>
    /// Placeholder for translateable strings
    /// </summary>
    public static class Strings
    {
        #region Command line
        /// <summary>
        /// A string displayed when the program is invoked without the correct number of arguments
        /// </summary>
        public static string CommandlineUsage = "Usage: SharpAESCrypt e|d[o][1-4] <password> [<fromPath> [<toPath>]]" +
            Environment.NewLine +
            Environment.NewLine + "Use 'e' or 'd' to specify operation: encrypt or decrypt." +
            Environment.NewLine + "Append an 'o' to the operation for optimistic mode. This will skip some tests and leaves partial/invalid files on disk." +
            Environment.NewLine + "Append a single number (up to 4) to the operation to set the number of threads used for crypting. Default is single thread mode (1)." +
            Environment.NewLine +
            Environment.NewLine + "If you ommit the fromPath or toPath, stdin/stdout are used insted, e.g.:" +
            Environment.NewLine + "  SharpAESCrypt e 1234 < file.jpg > file.jpg.aes" +
            Environment.NewLine + 
            Environment.NewLine + "Abnormal exit will return an errorlevel above 0 (zero):" +
            Environment.NewLine + "  4 - Password invalid" +
            Environment.NewLine + "  3 - HMAC Mismatch / altered data (also invalid password for version 0 files)" +
            Environment.NewLine + "  2 - Missing input stream / input file not found " +
            Environment.NewLine + "  1 - Any other cryptographic or IO exception "
            ;

        /// <summary>
        /// A string displayed when an error occurs while running the commandline program
        /// </summary>
        public static string CommandlineError = "Error: {0}";
        /// <summary>
        /// A string displayed if the mode is neither e nor d 
        /// </summary>
        public static string CommandlineUnknownMode = "Invalid operation, must be (e)ncrypt or (d)ecrypt";
        /// <summary>
        /// A string displayed on Commandline if input file is not found.
        /// </summary>
        public static string CommandlineInputFileNotFound = "Input file not found";

        #endregion

        #region Exception messages
        /// <summary>
        /// An exception message that indicates that the hash algorithm is not supported
        /// </summary>
        public static string UnsupportedHashAlgorithmReuse = "The hash algortihm does not support reuse";
        /// <summary>
        /// An exception message that indicates that the hash algorithm is not supported
        /// </summary>
        public static string UnsupportedHashAlgorithmBlocks = "The hash algortihm does not support multiple blocks";
        /// <summary>
        /// An exception message that indicates that the hash algorithm is not supported
        /// </summary>
        public static string UnsupportedHashAlgorithmBlocksize = "Unable to digest {0} bytes, as the hash algorithm only returns {1} bytes";
        /// <summary>
        /// An exception message that indicates that an unexpected end of stream was encountered
        /// </summary>
        public static string UnexpectedEndOfStream = "The stream was exhausted unexpectedly";
        /// <summary>
        /// An exception message that indicates that an unexpected size of a stream was encountered
        /// </summary>
        public static string StreamSizeMismatch = "Stream sizes do not match. This might be a bug.";
        /// <summary>
        /// An exception message that indicates that the stream does not support writing
        /// </summary>
        public static string StreamMustBeWriteAble = "When encrypting, the stream must be writeable";
        /// <summary>
        /// An exception messaget that indicates that the stream does not support reading
        /// </summary>
        public static string StreamMustBeReadAble = "When decrypting, the stream must be readable";
        /// <summary>
        /// An exception message that indicates that the mode is not one of the allowed enumerations
        /// </summary>
        public static string InvalidOperationMode = "Invalid mode supplied";

        /// <summary>
        /// An exception message that indicates that file is not in the correct format
        /// </summary>
        public static string InvalidFileFormat = "Invalid file format";
        /// <summary>
        /// An exception message that indicates that the header marker is invalid
        /// </summary>
        public static string InvalidHeaderMarker = "Invalid header marker";
        /// <summary>
        /// An exception message that indicates that the reserved field is not set to zero
        /// </summary>
        public static string InvalidReservedFieldValue = "Reserved field is not zero";
        /// <summary>
        /// An exception message that indicates that the detected file version is not supported
        /// </summary>
        public static string UnsupportedFileVersion = "Unsuported file version: {0}";
        /// <summary>
        /// An exception message that indicates that an extension had an invalid format
        /// </summary>
        public static string InvalidExtensionData = "Invalid extension data, separator (0x00) not found";
        /// <summary>
        /// An exception message that indicates that the format was accepted, but the password was not verified
        /// </summary>
        public static string InvalidPassword = "Invalid password or corrupted data";
        /// <summary>
        /// An exception message that indicates that the length of the file is incorrect
        /// </summary>
        public static string InvalidFileLength = "File length is invalid";

        /// <summary>
        /// An exception message that indicates that the version is readonly when decrypting
        /// </summary>
        public static string VersionReadonlyForDecryption = "Version is readonly when decrypting";
        /// <summary>
        /// An exception message that indicates that the file version is readonly once encryption has started
        /// </summary>
        public static string VersionReadonly = "Version cannot be changed after encryption has started";
        /// <summary>
        /// An exception message that indicates that the threading setting is readonly once crypting has started
        /// </summary>
        public static string ThreadingReadonly = "Threading mode cannot be changed after crypting has started";
        /// <summary>
        /// An exception message that indicates that the supplied version number is unsupported
        /// </summary>
        public static string VersionUnsupported = "The maximum allowed version is {0}";
        /// <summary>
        /// An exception message that indicates that the stream must support seeking
        /// </summary>
        public static string StreamMustSupportSeeking = "The stream must be seekable writing version 0 files";

        /// <summary>
        /// An exception message that indicates that the requsted operation is unsupported
        /// </summary>
        public static string CannotReadWhileEncrypting = "Cannot read while encrypting";
        /// <summary>
        /// An exception message that indicates that the requsted operation is unsupported
        /// </summary>
        public static string CannotWriteWhileDecrypting = "Cannot read while decrypting";

        /// <summary>
        /// An exception message that indicates that the requsted operation is not available.
        /// </summary>
        public static string HiddenBytesNotAvailable = "Hidden bytes not available before end of stream reached.";
        /// <summary>
        /// An exception message that indicates that the requsted operation is not available.
        /// </summary>
        public static string BufferTooSmall = "Internal buffers too small.";

        /// <summary>
        /// An exception message that indicates that the data has been altered
        /// </summary>
        public static string DataHMACMismatch = "Message has been altered, do not trust content";
        /// <summary>
        /// An exception message that indicates that the data has been altered or the password is invalid
        /// </summary>
        public static string DataHMACMismatch_v0 = "Invalid password or content has been altered";

        /// <summary>
        /// An exception message that indicates that the system is missing a text encoding
        /// </summary>
        public static string EncodingNotSupported = "The required encoding (UTF-16LE) is not supported on this system";
        #endregion
    }
    #endregion

    /// <summary>
    /// Provides a stream wrapping an AESCrypt file for either encryption or decryption.
    /// The file format declare support for 2^64 bytes encrypted data, but .Net has trouble 
    /// with files more than 2^63 bytes long, so this module 'only' supports 2^63 bytes 
    /// (long vs ulong).
    /// </summary>
    public class SharpAESCrypt : Stream
    {
        #region Shared constant values
        /// <summary>
        /// The header in an AESCrypt file
        /// </summary>
        private readonly byte[] MAGIC_HEADER = Encoding.UTF8.GetBytes("AES");

        /// <summary>
        /// The maximum supported file version
        /// </summary>
        public const byte MAX_FILE_VERSION = 2;

        /// <summary>
        /// The size of the block unit used by the algorithm in bytes
        /// </summary>
        public const int BLOCK_SIZE = 16;
        /// <summary>
        /// The size of the IV, in bytes, which is the same as the blocksize for AES
        /// </summary>
		public const int IV_SIZE = 16;
        /// <summary>
        /// The size of the key. For AES-256 that is 256/8 = 32
        /// </summary>
		public const int KEY_SIZE = 32;
        /// <summary>
        /// The size of the SHA-256 output, which matches the KEY_SIZE
        /// </summary>
        public const int HASH_SIZE = 32;
        /// <summary> Default number of threads to use </summary>
        public const int DEFAULT_THREADS = 1;

        #endregion

        #region Private instance variables
        /// <summary>
        /// The stream being encrypted or decrypted
        /// </summary>
        private Stream m_stream;
        /// <summary>
        /// The mode of operation
        /// </summary>
        private OperationMode m_mode;
        /// <summary>
        /// Helper payload stream for decryption, hiding bytes
        /// </summary>
        private StreamHider m_payloadStream;

        /// <summary>
        /// Top of stack / end of pipe stream performing crypt operation.
        /// Actual Type depends on threading mode.
        /// </summary>
        private Stream m_cryptDataStream;
        /// <summary>
        /// The main (first tier) DataPump when multi-threading (null otherwise).
        /// Used for synchronization and exception detection.
        /// </summary>
        private DirectStreamLink.DataPump m_cryptoThreadPump;
        
        /// <summary>
        /// The HMAC used for validating data
        /// </summary>
        private HMAC m_hmac;
        /// <summary>
        /// The length of the data modulus <see cref="BLOCK_SIZE"/>
        /// </summary>
        private int m_length;
        /// <summary>
        /// The setup helper instance
        /// </summary>
        private SetupHelper m_helper;
        /// <summary>
        /// The list of extensions read from or written to the stream
        /// </summary>
        private List<KeyValuePair<string, byte[]>> m_extensions;
        /// <summary>
        /// The file format version
        /// </summary>
        private byte m_version = MAX_FILE_VERSION;
        /// <summary>
        /// Set number of threads to be used for crypto-operations:
        /// 1 for no multithreading at all, 2 for separate hashing, > 2 for AES-stream splitting
        /// </summary>
        private int m_maxCryptoThreads = DEFAULT_THREADS;

        /// <summary>
        /// True if the header is written, false otherwise. Used only for encryption.
        /// </summary>
        private bool m_hasWrittenHeader = false;
        /// <summary>
        /// True if the footer has been written, false otherwise. Used only for encryption.
        /// </summary>
        private bool m_hasFlushedFinalBlock = false;
        /// <summary>
        /// The number of bytes read from the encrypted stream. Used only for decryption.
        /// </summary>
        private long m_readcount;
        /// <summary>
        /// The number of padding bytes. Used only for decryption.
        /// </summary>
        private byte m_paddingSize;
        /// <summary>
        /// True if the header HMAC has been read and verified, false otherwise. Used only for decryption.
        /// </summary>
        private bool m_hasReadFooter = false;

        /// <summary> Buffer to support read-ahead on decrypt.</summary>
        private byte[] m_nextBlock;
        /// <summary> Buffer to support read-ahead on decrypt.</summary>
        private byte[] m_curBlock;
        /// <summary> Number of bytes in read-ahead buffer.</summary>
        private int m_curBlockBytes;

        #endregion

        #region Private helper functions and properties
        /// <summary>
        /// Helper property to ensure that the crypto stream is initialized before being used
        /// </summary>
        private Stream Crypto
        {
            get
            {
                if (m_cryptDataStream == null)
                {
                    switch (m_mode)
                    {
                        case OperationMode.Encrypt:
                            WriteEncryptionHeader();
                            InitStreamsEncryption();
                            break;
                        case OperationMode.Decrypt:
                            InitStreamsDecryption();
                            break;
                    }
                }
                return m_cryptDataStream;
            }
        }

        /// <summary> Init streams for decryption. Simple stack for single thread. For multithreading, sets up pipes and runs data pumps. </summary>
        private void InitStreamsDecryption()
        {
            m_hmac = m_helper.GetHMAC();
            //Insert the HMAC before the decryption so the HMAC is calculated for the ciphertext
            m_payloadStream = new StreamHider(m_stream, m_version == 0 ? HASH_SIZE : (HASH_SIZE + 1));

            if (m_maxCryptoThreads > 1)
            {
                int useAesThreads = Math.Min(Environment.ProcessorCount, m_maxCryptoThreads - 1);
                List<DirectStreamLink.DataPump> dataPumps = new List<DirectStreamLink.DataPump>();

                if (useAesThreads > 1) // multiple AES threads: we will split the stream to chunks and have several decoders.
                {
                    // Make sure there are enough threads available in threadpool (we work blocking, so otherwise it takes time to trigger start of new pool threads).
                    // This is important because of the Close() operations in StreamStriper. This will stall for 0,5 secs per thread on first iteration.
                    int cWorker, cIO;
                    ThreadPool.GetMinThreads(out cWorker, out cIO);
                    if (cWorker < 4 + 3 * (useAesThreads + 1))
                        ThreadPool.SetMinThreads(4 + 3 * (useAesThreads + 1), cIO);

                    int useChunkSize = 1 << 14; // MUST be a multiple of BLOCK_SIZE for splitting to work!
                    //if modifiable, check: if (useChunkSize % BLOCK_SIZE != 0) throw new Exception();

                    // First we have to set up all the worker streams:
                    Stream[] cryptoInputWriters = new Stream[useAesThreads];
                    Stream[] cryptoOutputReaders = new Stream[useAesThreads];
                    for (int t = 0; t < useAesThreads; t++)
                    {
                        var linkCryptInput = new DirectStreamLink(4 * (useChunkSize + BLOCK_SIZE), false, true, null);
                        var linkCryptOutput = new DirectStreamLink(4 * (useChunkSize + BLOCK_SIZE), false, true, null);
                        // we use ClosingCryptoStream to make sure base streams are also closed (for synchronization)
                        var cryptoStream = new ClosingCryptoStream(linkCryptOutput.WriterStream, m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Write);
                        cryptoInputWriters[t] = linkCryptInput.WriterStream;
                        cryptoOutputReaders[t] = linkCryptOutput.ReaderStream;

                        // Note: DataPump's bufsize must be smaller than buffer in input stream. Otherwise CryptoReader could block waiting for data
                        //       We add a handler to call FluhFinalBlock, even though that should not be necessary
                        DirectStreamLink.DataPump cryptoPump =
                            new DirectStreamLink.DataPump(linkCryptInput.ReaderStream, cryptoStream, (useChunkSize + 1 * BLOCK_SIZE), (p) => cryptoStream.FlushFinalBlock());

                        dataPumps.Add(cryptoPump);
                    }

                    OverlappedStreamStriper cryptSplitter = new OverlappedStreamStriper(OverlappedStreamStriper.Mode.Split, cryptoInputWriters, useChunkSize, BLOCK_SIZE);
                    OverlappedStreamStriper decryptJoiner = new OverlappedStreamStriper(OverlappedStreamStriper.Mode.Join, cryptoOutputReaders, useChunkSize, BLOCK_SIZE);

                    CryptoStream hasher = new ClosingCryptoStream(cryptSplitter, m_hmac, CryptoStreamMode.Write);
                    m_cryptDataStream = decryptJoiner;
                    m_cryptoThreadPump = new DirectStreamLink.DataPump(m_payloadStream, hasher);
                
                }
                else // only single AES thread: plug directly to LinkStream (will run in main thread)
                {
                    CryptoStream hasher = new ClosingCryptoStream(Stream.Null, m_hmac, CryptoStreamMode.Write);
                    DirectStreamLink linkHasherToCrypto = new DirectStreamLink(1 << 16, false, true, hasher);
                    // we use ClosingCryptoStream to make sure base streams are also closed (for synchronization)
                    m_cryptDataStream = new ClosingCryptoStream(linkHasherToCrypto.ReaderStream, m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Read);
                    m_cryptoThreadPump = new DirectStreamLink.DataPump(m_payloadStream, linkHasherToCrypto.WriterStream);
                }

                // Start pumping data through our threads
                m_cryptoThreadPump.RunInThreadPool(true); // with WaitHandle for synchronization
                foreach (var pump in dataPumps) pump.RunInThreadPool(false); //no WaitHandles, synched through DirectStreamLink
            }
            else
            {
                CryptoStream hasher = new CryptoStream(m_payloadStream, m_hmac, CryptoStreamMode.Read);
                m_cryptDataStream = new CryptoStream(hasher, m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Read);
                m_cryptoThreadPump = null;
            }
        }

        /// <summary>
        /// Helper function to read and validate the header
        /// </summary>
        private void ReadEncryptionHeader(string password, bool skipFileSizeCheck)
        {
            byte[] tmp = new byte[MAGIC_HEADER.Length + 2];

            if (ForceRead(m_stream, tmp, 0, tmp.Length) < tmp.Length)
                throw new InvalidDataException(Strings.InvalidHeaderMarker);

            for (int i = 0; i < MAGIC_HEADER.Length; i++)
                if (MAGIC_HEADER[i] != tmp[i])
                    throw new InvalidDataException(Strings.InvalidHeaderMarker);

            m_version = tmp[MAGIC_HEADER.Length];
            if (m_version > MAX_FILE_VERSION)
                throw new InvalidDataException(string.Format(Strings.UnsupportedFileVersion, m_version));

            if (m_version == 0)
            {
                m_paddingSize = tmp[MAGIC_HEADER.Length + 1];
                if (m_paddingSize >= BLOCK_SIZE)
                    throw new InvalidDataException(Strings.InvalidHeaderMarker);
            }
            else if (tmp[MAGIC_HEADER.Length + 1] != 0)
                throw new InvalidDataException(Strings.InvalidReservedFieldValue);

            //Extensions are only supported in v2+
            if (m_version >= 2)
            {
                int extensionLength = 0;
                do
                {
                    byte[] tmpLength = RepeatRead(m_stream, 2);
                    extensionLength = (((int)tmpLength[0]) << 8) | (tmpLength[1]);

                    if (extensionLength != 0)
                    {
                        byte[] data = RepeatRead(m_stream, extensionLength);
                        int separatorIndex = Array.IndexOf<byte>(data, 0);
                        if (separatorIndex < 0)
                            throw new InvalidDataException(Strings.InvalidExtensionData);

                        string key = System.Text.Encoding.UTF8.GetString(data, 0, separatorIndex);
                        byte[] value = new byte[data.Length - separatorIndex - 1];
                        Array.Copy(data, separatorIndex + 1, value, 0, value.Length);

                        m_extensions.Add(new KeyValuePair<string, byte[]>(key, value));
                    }

                } while (extensionLength > 0);
            }

            byte[] iv1 = RepeatRead(m_stream, IV_SIZE);
            m_helper = new SetupHelper(m_mode, password, iv1);

            long payloadLength = -1;
            if (m_version >= 1)
            {
                byte[] hmac1 = m_helper.DecryptAESKey2(RepeatRead(m_stream, IV_SIZE + KEY_SIZE));
                byte[] hmac2 = RepeatRead(m_stream, hmac1.Length);
                for (int i = 0; i < hmac1.Length; i++)
                    if (hmac1[i] != hmac2[i])
                        throw new WrongPasswordException(Strings.InvalidPassword);

                if (m_stream.CanSeek)
                {
                    try { payloadLength = m_stream.Length - m_stream.Position - (HASH_SIZE + 1); }
                    catch { payloadLength = -1; }
                }
            }
            else
            {
                m_helper.SetBulkKeyToKey1();

                if (m_stream.CanSeek)
                {
                    try { payloadLength = m_stream.Length - m_stream.Position - HASH_SIZE; }
                    catch { payloadLength = -1; }
                }
            }

            if (!skipFileSizeCheck && payloadLength != -1 && (payloadLength % BLOCK_SIZE != 0))
                throw new CryptographicException(Strings.InvalidFileLength);
        }


        /// <summary> Init streams for encryption. Simple stack for single thread. For multithreading, sets up a pipe and runs data pump. </summary>
        private void InitStreamsEncryption()
        {
            m_hmac = m_helper.GetHMAC();
            //Insert the HMAC before the stream to calculate the HMAC for the ciphertext
            if (m_maxCryptoThreads > 1)
            {
                // We ask DirectLinkStream to block until reader closes and has thus written all
                // data to m_hasher. m_hasher's close is separately handled
                DirectStreamLink link = new DirectStreamLink(1 << 16, true, true, new LeaveOpenStream(m_stream));
                m_cryptDataStream = new ClosingCryptoStream(link.WriterStream, m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Write);
                // we use ClosingCryptoStream to make sure base streams are also closed (for synchronization)
                CryptoStream hasher = new ClosingCryptoStream(Stream.Null, m_hmac, CryptoStreamMode.Write);
                m_cryptoThreadPump = new DirectStreamLink.DataPump(link.ReaderStream, hasher);
                m_cryptoThreadPump.RunInThreadPool(true);  // with WaitHandle for synchronization
            }
            else
            {
                CryptoStream hasher = new CryptoStream(new LeaveOpenStream(m_stream), m_hmac, CryptoStreamMode.Write);
                m_cryptDataStream = new CryptoStream(hasher, m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Write);
                m_cryptoThreadPump = null;
            }

        }

        /// <summary>
        /// Writes the header to the output stream and sets up the crypto stream
        /// </summary>
        private void WriteEncryptionHeader()
        {
            m_stream.Write(MAGIC_HEADER, 0, MAGIC_HEADER.Length);
            m_stream.WriteByte(m_version);
            m_stream.WriteByte(0); //Reserved or length % 16
            if (m_version >= 2)
            {
                foreach (KeyValuePair<string, byte[]> ext in m_extensions)
                    WriteExtension(ext.Key, ext.Value);
                m_stream.Write(new byte[] { 0, 0 }, 0, 2); //No more extensions
            }

            m_stream.Write(m_helper.IV1, 0, m_helper.IV1.Length);

            if (m_version == 0)
                m_helper.SetBulkKeyToKey1();
            else
            {
                //Generate and encrypt bulk key and its HMAC
                byte[] tmpKey = m_helper.EncryptAESKey2();
                m_stream.Write(tmpKey, 0, tmpKey.Length);
                tmpKey = m_helper.CalculateKeyHmac();
                m_stream.Write(tmpKey, 0, tmpKey.Length);
            }

            m_hasWrittenHeader = true;
        }

        /// <summary>
        /// Writes an extension to the output stream, see:
        /// http://www.aescrypt.com/aes_file_format.html
        /// </summary>
        /// <param name="identifier">The extension identifier</param>
        /// <param name="value">The data to set in the extension</param>
        private void WriteExtension(string identifier, byte[] value)
        {
            byte[] name = System.Text.Encoding.UTF8.GetBytes(identifier);
            if (value == null)
                value = new byte[0];

            uint size = (uint)(name.Length + 1 + value.Length);
            m_stream.WriteByte((byte)((size >> 8) & 0xff));
            m_stream.WriteByte((byte)(size & 0xff));
            m_stream.Write(name, 0, name.Length);
            m_stream.WriteByte(0);
            m_stream.Write(value, 0, value.Length);
        }

        #endregion

        #region Private utility classes and functions
        /// <summary>
        /// Internal helper class used to encapsulate the setup process
        /// </summary>
        private class SetupHelper : IDisposable
        {
            /// <summary>
            /// The MAC adress to use in case the network interface enumeration fails
            /// </summary>
            private static readonly byte[] DEFAULT_MAC = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

            /// <summary>
            /// The hashing algorithm used to digest data
            /// </summary>
            private const string HASH_ALGORITHM = "SHA-256";

            /// <summary>
            /// The choice of algorithms used to encrypt and decrypt data.
            /// Supports AesCryptoServiceProvider to employ HW accelerated (AES-NI) crypting on Win8+.
            /// Sadly, a workaround to load AesCryptoServiceProvider has to be employed to not break 2.0-compatibility
            /// as the .NET team seems to have forgotten to register the name "AES" in .Net 3.5...
            /// </summary>
            private readonly string[] CRYPT_ALGORITHMS = new string[] 
            {
                "AES", // only works for .NET4+
                // The TypeAQN works (in Win) when any .NET-Framework >= v3.5 is installed.
                "TYPEAQN:System.Security.Cryptography.AesCryptoServiceProvider, System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089", 
                "Rijndael" // fallback if .NET < v3.5 installed, or outdated MONO
            };

            /// <summary>
            /// The algorithm used to generate random data
            /// </summary>
            private const string RAND_ALGORITHM = "SHA1PRNG";

            /// <summary>
            /// The algorithm used to calculate the HMAC
            /// </summary>
            private const string HMAC_ALGORITHM = "HmacSHA256";

            /// <summary>
            /// The encoding scheme for the password.
            /// UTF-16 should mean UTF-16LE, but Mono rejects the full name.
            /// A check is made when using the encoding, that it is indeed UTF-16LE.
            /// </summary>
            private const string PASSWORD_ENCODING = "utf-16";

            /// <summary>
            /// The symmetric algorithm type to be used. Will be set and resolved on first instantiation.
            /// </summary>
            private static Type m_useSymmetricAlgorithmType = null;

            /// <summary>
            /// The encryption instance
            /// </summary>
            private SymmetricAlgorithm m_crypt;
            /// <summary>
            /// The hash instance
            /// </summary>
            private HashAlgorithm m_hash;
            /// <summary>
            /// The random number generator instance
            /// </summary>
            private RandomNumberGenerator m_rand;
            /// <summary>
            /// The HMAC algorithm
            /// </summary>
            private HMAC m_hmac;

            /// <summary>
            /// The IV used to encrypt/decrypt the bulk key
            /// </summary>
            private byte[] m_iv1;
            /// <summary>
            /// The private key used to encrypt/decrypt the bulk key
            /// </summary>
            private byte[] m_aesKey1;
            /// <summary>
            /// The IV used to encrypt/decrypt bulk data
            /// </summary>
            private byte[] m_iv2;
            /// <summary>
            /// The key used to encrypt/decrypt bulk data
            /// </summary>
            private byte[] m_aesKey2;


            /// <summary>
            /// Helper function to resolve an algorithm name or type assembly qualified name to a type.
            /// Can be used for any type of Crypto-classes.
            /// </summary>
            private Type resolveCryptoAlgorithm<T>(IList<string> cryptoAlgoNames, out T retAlgoInst) where T : class
            {
                Type retAlgoType = null; retAlgoInst = null;
                foreach (var algo in cryptoAlgoNames)
                {
                    if (algo.StartsWith("TYPEAQN:"))
                    {
                        var typeaqn = algo.Substring("TYPEAQN:".Length);
                        retAlgoType = Type.GetType(typeaqn);
                        if (retAlgoType != null)
                        {
                            retAlgoInst = Activator.CreateInstance(retAlgoType) as T;
                            break;
                        }
                    }
                    else
                    {
                        retAlgoInst = CryptoConfig.CreateFromName(algo) as T;
                        if (retAlgoInst != null)
                        {
                            retAlgoType = retAlgoInst.GetType();
                            break;
                        }
                    }
                }
                return retAlgoType;
            }

            /// <summary>
            /// Initialize the setup
            /// </summary>
            /// <param name="mode">The mode to prepare for</param>
            /// <param name="password">The password used to encrypt or decrypt</param>
            /// <param name="iv">The IV used, set to null if encrypting</param>
            public SetupHelper(OperationMode mode, string password, byte[] iv)
            {
                // Check for AES-implementation to use and save that type for subsequent calls.
                if (m_useSymmetricAlgorithmType == null)
                    m_useSymmetricAlgorithmType = resolveCryptoAlgorithm(CRYPT_ALGORITHMS, out m_crypt);
                else
                    m_crypt = (SymmetricAlgorithm) Activator.CreateInstance(m_useSymmetricAlgorithmType);

                //Not sure how to insert this with the CRYPT_ALGORITHM string
                m_crypt.Padding = PaddingMode.None;
                m_crypt.Mode = CipherMode.CBC;
                m_crypt.BlockSize = BLOCK_SIZE * 8;
                m_crypt.KeySize = KEY_SIZE * 8;

				// TODO: Change back once we upgrade beyond netcore 2.0
				//m_hash = HashAlgorithm.Create(HASH_ALGORITHM);
				//m_hmac = HMAC.Create(HMAC_ALGORITHM);

				m_hash = (HashAlgorithm)CryptoConfig.CreateFromName(HASH_ALGORITHM);
                m_rand = RandomNumberGenerator.Create(/*RAND_ALGORITHM*/);
				m_hmac = (HMAC)CryptoConfig.CreateFromName(HMAC_ALGORITHM);

                if (mode == OperationMode.Encrypt)
                {
                    m_iv1 = GenerateIv1();
                    m_aesKey1 = GenerateAESKey1(EncodePassword(password));
                    m_iv2 = GenerateIv2();
                    m_aesKey2 = GenerateAESKey2();
                }
                else
                {
                    m_iv1 = iv;
                    m_aesKey1 = GenerateAESKey1(EncodePassword(password));
                }
            }

            /// <summary>
            /// Encodes the password in UTF-16LE, 
            /// used to fix missing support for the full encoding 
            /// name under Mono. Verifies that the encoding is correct.
            /// </summary>
            /// <param name="password">The password to encode as a byte array</param>
            /// <returns>The password encoded as a byte array</returns>
            private byte[] EncodePassword(string password)
            {
                Encoding e = Encoding.GetEncoding(PASSWORD_ENCODING);

                byte[] preamb = e == null ? null : e.GetPreamble();
                if (preamb == null || preamb.Length != 2)
                    throw new SystemException(Strings.EncodingNotSupported);

                if (preamb[0] == 0xff && preamb[1] == 0xfe)
                    return e.GetBytes(password);
                else if (preamb[0] == 0xfe && preamb[1] == 0xff)
                {
                    //We have a Big Endian, convert to Little endian
                    byte[] tmp = e.GetBytes(password);
                    if (tmp.Length % 2 != 0)
                        throw new SystemException(Strings.EncodingNotSupported);

                    for (int i = 0; i < tmp.Length; i += 2)
                    {
                        byte x = tmp[i];
                        tmp[i] = tmp[i + 1];
                        tmp[i + 1] = x;
                    }

                    return tmp;
                }
                else
                    throw new SystemException(Strings.EncodingNotSupported);
            }

            /// <summary>
            /// Gets the IV used to encrypt the bulk data key
            /// </summary>
            public byte[] IV1
            {
                get { return m_iv1; }
            }


            /// <summary>
            /// Creates the iv used for encrypting the bulk key and IV.
            /// </summary>
            /// <returns>A random IV</returns>
            private byte[] GenerateIv1()
            {
                byte[] iv = new byte[IV_SIZE];
                long time = DateTime.Now.Ticks;
                byte[] mac = null;

                /**********************************************************************
                *                                                                     *
                *   NOTE: The time and mac are COMPONENTS in the random IV input.     *
                *         The IV does not require the time or mac to be random.       *
                *                                                                     *
                *         The mac and time are used to INCREASE the ENTROPY, and      *
                *         DECOUPLE the IV from the PRNG output, in case the PRNG      *
                *         has a defect (intentional or not)                           *
                *                                                                     *
                *         Please review the DigestRandomBytes method before           *
                *         INCORRECTLY ASSUMING that the IV is generated from          *
                *         time and mac inputs.                                        *
                *                                                                     *
                ***********************************************************************/

                try
                {
                    System.Net.NetworkInformation.NetworkInterface[] interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
                    for (int i = 0; i < interfaces.Length; i++)
                        if (i != System.Net.NetworkInformation.NetworkInterface.LoopbackInterfaceIndex)
                        {
                            mac = interfaces[i].GetPhysicalAddress().GetAddressBytes();
                            break;
                        }
                }
                catch
                {
                    //Not much to do, just go with default MAC
                }

                if (mac == null)
                    mac = DEFAULT_MAC;

                for (int i = 0; i < 8; i++)
                    iv[i] = (byte)((time >> (i * 8)) & 0xff);

                Array.Copy(mac, 0, iv, 8, Math.Min(mac.Length, iv.Length - 8));
                return DigestRandomBytes(iv, 256);
            }

            /// <summary>
            /// Generates a key based on the IV and the password.
            /// This key is used to encrypt the actual key and IV.
            /// </summary>
            /// <param name="password">The password supplied</param>
            /// <returns>The key generated</returns>
            private byte[] GenerateAESKey1(byte[] password)
            {
                if (!m_hash.CanReuseTransform)
                    throw new CryptographicException(Strings.UnsupportedHashAlgorithmReuse);
                if (!m_hash.CanTransformMultipleBlocks)
                    throw new CryptographicException(Strings.UnsupportedHashAlgorithmBlocks);

                if (KEY_SIZE < m_hash.HashSize / 8)
                    throw new CryptographicException(string.Format(Strings.UnsupportedHashAlgorithmBlocksize, KEY_SIZE, m_hash.HashSize / 8));

                byte[] key = new byte[KEY_SIZE];
                Array.Copy(m_iv1, key, m_iv1.Length);

                for (int i = 0; i < 8192; i++)
                {
                    m_hash.Initialize();
                    m_hash.TransformBlock(key, 0, key.Length, key, 0);
                    m_hash.TransformFinalBlock(password, 0, password.Length);
                    key = m_hash.Hash;
                }

                return key;
            }

            /// <summary>
            /// Generates a random IV for encrypting data
            /// </summary>
            /// <returns>A random IV</returns>
            private byte[] GenerateIv2()
            {
                m_crypt.GenerateIV();
                return DigestRandomBytes(m_crypt.IV, 256);
            }

            /// <summary>
            /// Generates a random key for encrypting data
            /// </summary>
            /// <returns></returns>
            private byte[] GenerateAESKey2()
            {
                m_crypt.GenerateKey();
                return DigestRandomBytes(m_crypt.Key, 32);
            }

            /// <summary>
            /// Encrypts the key and IV used to encrypt data with the initial key and IV.
            /// </summary>
            /// <returns>The encrypted AES Key (including IV)</returns>
            public byte[] EncryptAESKey2()
            {
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, m_crypt.CreateEncryptor(m_aesKey1, m_iv1), CryptoStreamMode.Write))
                {
                    cs.Write(m_iv2, 0, m_iv2.Length);
                    cs.Write(m_aesKey2, 0, m_aesKey2.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }

            /// <summary>
            /// Calculates the HMAC for the encrypted key
            /// </summary>
            /// <returns>The HMAC value</returns>
            public byte[] CalculateKeyHmac()
            {
                m_hmac.Initialize();
                m_hmac.Key = m_aesKey1;
                return m_hmac.ComputeHash(EncryptAESKey2());
            }

            /// <summary>
            /// Performs repeated hashing of the data in the byte[] combined with random data.
            /// The update is performed on the input data, which is also returned.
            /// </summary>
            /// <param name="bytes">The bytes to start the digest operation with</param>
            /// <param name="repetitions">The number of repetitions to perform</param>
            /// <returns>The digested input data, which is the same array as passed in</returns>
            private byte[] DigestRandomBytes(byte[] bytes, int repetitions)
            {
                if (bytes.Length > (m_hash.HashSize / 8))
                    throw new CryptographicException(string.Format(Strings.UnsupportedHashAlgorithmBlocksize, bytes.Length, m_hash.HashSize / 8));

                if (!m_hash.CanReuseTransform)
                    throw new CryptographicException(Strings.UnsupportedHashAlgorithmReuse);
                if (!m_hash.CanTransformMultipleBlocks)
                    throw new CryptographicException(Strings.UnsupportedHashAlgorithmBlocks);

                m_hash.Initialize();
                m_hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                for (int i = 0; i < repetitions; i++)
                {
                    m_rand.GetBytes(bytes);
                    m_hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                }

                m_hash.TransformFinalBlock(bytes, 0, 0);
                Array.Copy(m_hash.Hash, bytes, bytes.Length);
                return bytes;
            }

            /// <summary>
            /// Generates the CryptoTransform element used to encrypt/decrypt the bulk data
            /// </summary>
            /// <param name="mode">The operation mode</param>
            /// <returns>An ICryptoTransform instance</returns>
            public ICryptoTransform CreateCryptoStream(OperationMode mode)
            {
                if (mode == OperationMode.Encrypt)
                    return m_crypt.CreateEncryptor(m_aesKey2, m_iv2);
                else
                    return m_crypt.CreateDecryptor(m_aesKey2, m_iv2);
            }

            /// <summary>
            /// Creates a fresh HMAC calculation algorithm
            /// </summary>
            /// <returns>An HMAC algortihm using AES Key 2</returns>
            public HMAC GetHMAC()
            {
				// TODO: Change back once we upgrade beyond netcore 2.0
				//HMAC h = HMAC.Create (HMAC_ALGORITHM);
				var h = (HMAC)CryptoConfig.CreateFromName(HMAC_ALGORITHM);
                h.Key = m_aesKey2;
                return h;
            }

            /// <summary>
            /// Decrypts the bulk key and IV
            /// </summary>
            /// <param name="data">The encrypted IV followed by the key</param>
            /// <returns>The HMAC value for the key</returns>
            public byte[] DecryptAESKey2(byte[] data)
            {
                using (MemoryStream ms = new MemoryStream(data))
                using (CryptoStream cs = new CryptoStream(ms, m_crypt.CreateDecryptor(m_aesKey1, m_iv1), CryptoStreamMode.Read))
                {
                    m_iv2 = RepeatRead(cs, IV_SIZE);
                    m_aesKey2 = RepeatRead(cs, KEY_SIZE);
                }

                m_hmac.Initialize();
                m_hmac.Key = m_aesKey1;
                m_hmac.TransformFinalBlock(data, 0, data.Length);
                return m_hmac.Hash;
            }

            /// <summary>
            /// Sets iv2 and aesKey2 to iv1 and aesKey1 respectively.
            /// Used only for files with version = 0
            /// </summary>
            public void SetBulkKeyToKey1()
            {
                m_iv2 = m_iv1;
                m_aesKey2 = m_aesKey1;
            }

            #region IDisposable Members

            /// <summary>
            /// Disposes all members 
            /// </summary>
            public void Dispose()
            {
                if (m_crypt != null)
                {
                    if (m_aesKey1 != null)
                        Array.Clear(m_aesKey1, 0, m_aesKey1.Length);
                    if (m_iv1 != null)
                        Array.Clear(m_iv1, 0, m_iv1.Length);
                    if (m_aesKey2 != null)
                        Array.Clear(m_aesKey2, 0, m_aesKey2.Length);
                    if (m_iv2 != null)
                        Array.Clear(m_iv2, 0, m_iv2.Length);

                    m_aesKey1 = null;
                    m_iv1 = null;
                    m_aesKey2 = null;
                    m_iv2 = null;

                    m_hash = null;
                    m_hmac = null;
                    m_rand = null;
                    m_crypt = null;
                }
            }

            #endregion
        }

        /// <summary>
        /// Private helper class fixing a bug in .NET:
        /// CryptoStream fails to close it's base stream on a cryptographic exception (last block incomplete).
        /// This class forces a close on exception for erroneous streams. Necessary to allow threads to end.
        /// </summary>
        private class ClosingCryptoStream : CryptoStream
        {
            private readonly Stream baseStream;
            public ClosingCryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
                : base(stream, transform, mode)
            { this.baseStream = stream; }

            protected override void Dispose(bool disposing)
            {   // Close underlying stream if exception was thrown in base, then rethrow.
                try { base.Dispose(disposing); }
                catch (Exception)
                { if (disposing) try { this.baseStream.Close(); } catch { } throw; }
            }
        }

        /// <summary>
        /// Internal helper class, used to prevent a overlay stream from closing its base
        /// </summary>
        private class LeaveOpenStream : Stream
        {
            /// <summary> The wrapped stream </summary>
            private Stream m_stream;

            public LeaveOpenStream(Stream stream)
            { m_stream = stream; }

            #region Basic Stream implementation stuff
            public override bool CanRead { get { return m_stream.CanRead; } }
            public override bool CanSeek { get { return m_stream.CanSeek; } }
            public override bool CanWrite { get { return m_stream.CanWrite; } }
            public override void Flush() { m_stream.Flush(); }
            public override long Length { get { return m_stream.Length; } }
            public override long Seek(long offset, SeekOrigin origin) { return m_stream.Seek(offset, origin); }
            public override void SetLength(long value) { m_stream.SetLength(value); }
            public override long Position { get { return m_stream.Position; } set { m_stream.Position = value; } }
            public override int Read(byte[] buffer, int offset, int count){ return m_stream.Read(buffer, offset, count); }
            public override void Write(byte[] buffer, int offset, int count) { m_stream.Write(buffer, offset, count); }
            #endregion
        }

        /// <summary>
        /// Internal helper class, used to hide the trailing bytes from the cryptostream
        /// </summary>
        private class StreamHider : Stream
        {
            /// <summary>
            /// The wrapped stream
            /// </summary>
            private Stream m_stream;

            /// <summary> End of file reached. </summary>
            private bool m_eof;

            /// <summary>
            /// The number of bytes to hide
            /// </summary>
            private int m_hiddenByteCount;

            /// <summary>
            /// Buffers data and remains hidden bytes after read
            /// </summary>
            private byte[] m_intbuf;

            /// <summary>
            /// Will store the hidden bytes after eof found.
            /// This will be kept available after close.
            /// </summary>
            private byte[] m_finalHiddenBytes;

            /// <summary> size of intbuf </summary>
            private int m_bufsize;
            /// <summary> Total bytes read from intbuf </summary>
            private long m_read = 0;
            /// <summary> Total bytes written to intbuf </summary>
            private long m_written = 0;

            /// <summary>
            /// Constructs the stream wrapper to hide the desired bytes
            /// </summary>
            /// <param name="stream">The stream to wrap</param>
            /// <param name="count">The number of bytes to hide</param>
            public StreamHider(Stream stream, int count)
                : this(stream, count, 1 << 16)
            { }

            /// <summary>
            /// Constructs the stream wrapper to hide the desired bytes
            /// </summary>
            /// <param name="stream">The stream to wrap</param>
            /// <param name="count">The number of bytes to hide</param>
            /// <param name="bufsize">The internal buffer size to use. Default is 4K.</param>
            public StreamHider(Stream stream, int count, int bufsize)
            {
                m_stream = stream;
                m_hiddenByteCount = count;
                if (bufsize < (count * 2)) bufsize = (count * 2); else bufsize = bufsize + count;
                m_bufsize = bufsize;
                m_intbuf = null;
                m_read = m_written = 0;
                m_eof = false;
            }

            private void initIntBuf()
            {
                m_intbuf = new byte[m_bufsize];
                int bytesRead = 0;
                int c = 0;
                while ((c = m_stream.Read(m_intbuf, bytesRead, m_bufsize - bytesRead)) != 0)
                { bytesRead += c; if (bytesRead >= m_hiddenByteCount) break; }
                m_written += bytesRead;
                if (c == 0) // premature end. Store in m_finalHiddenBytes anyway, throw on access there.
                {
                    m_eof = true;
                    m_finalHiddenBytes = peekLastBytesFromIntBuf(m_hiddenByteCount);
                }
            }

            /// <summary> The currently known length of the payload. Negative if base stream shorter than hidden bytes in base stream.  </summary>
            public long PayloadLength { get { return m_written - m_hiddenByteCount; } }

            #region Basic Stream implementation stuff
            public override bool CanRead { get { return m_stream.CanRead; } }
            public override bool CanSeek { get { return m_stream.CanSeek; } }
            public override bool CanWrite { get { return m_stream.CanWrite; } }
            public override void Flush() { m_stream.Flush(); }
            public override long Length { get { return m_stream.Length - m_hiddenByteCount; } }
            public override long Seek(long offset, SeekOrigin origin) { return m_stream.Seek(offset, origin); }
            public override void SetLength(long value) { m_stream.SetLength(value + m_hiddenByteCount); }
            public override long Position { get { return m_stream.Position; } set { m_stream.Position = value; } }
            public override void Write(byte[] buffer, int offset, int count) { m_stream.Write(buffer, offset, count); }
            #endregion

            /// <summary>
            /// Return the hidden bytes. Available only after stream has been read to end.
            /// </summary>
            public byte[] GetHiddenBytes(int offset, int count)
            {
                // optimistic read if caller knew the end before, but we don't
                if (!m_eof && m_written == m_read + m_hiddenByteCount)
                    readToIntBuf(m_stream);

                if (m_eof)
                {
                    // this class is designed to actually store hidden bytes even if the stream is too short.
                    // if ever needed, remove this check to access bytes if base stream was to short.
                    if (m_finalHiddenBytes == null || m_finalHiddenBytes.Length < m_hiddenByteCount)
                        throw new IOException(Strings.UnexpectedEndOfStream);

                    if (count < 0 || offset < 0 || count + offset > m_hiddenByteCount)
                        throw new ArgumentException();

                    byte[] retBytes = new byte[count];
                    Array.Copy(m_finalHiddenBytes, offset, retBytes, 0, count);
                    return retBytes;
                }
                else throw new InvalidOperationException(Strings.HiddenBytesNotAvailable);
            }

            /// <summary> Writes to internal buffer. Guarantees to write all, throws otherwise. </summary>
            private void writeToIntBuf(byte[] buffer, int offset, int count)
            {
                if (count == 0) return;
                if (count > (m_intbuf.Length - m_written + m_read))
                    throw new InvalidOperationException(Strings.BufferTooSmall);
                int startIndex = (int)(m_written % m_intbuf.Length);
                int round1 = Math.Min(count, m_intbuf.Length - startIndex);
                Array.Copy(buffer, offset, m_intbuf, startIndex, round1);
                if (count > round1)
                    Array.Copy(buffer, offset + round1, m_intbuf, 0, count - round1);
                m_written += count;
            }

            /// <summary> Reads from stream to internal buffer as much as fits or is available. </summary>
            private int readToIntBuf(Stream stream)
            {
                int bufFree = (int)(m_intbuf.Length - m_written + m_read);
                if (bufFree<= 0)
                    throw new InvalidOperationException(Strings.BufferTooSmall);
                int offset = (int)(m_written % m_intbuf.Length);
                int round1 = Math.Min(bufFree, m_intbuf.Length - offset);
                int bytesRead = stream.Read(m_intbuf, offset, round1);
                bufFree -= bytesRead;
                if (bytesRead == round1 && bufFree > 0)
                    bytesRead += stream.Read(m_intbuf, 0, bufFree);
                m_written += bytesRead;
                return bytesRead;
            }

            /// <summary> Reads from internal buffer. Guarantees to read maximum available. </summary>
            private int readFromIntBuf(byte[] buffer, int offset, int count)
            {
                count = Math.Min(count, (int)(m_written - m_read));
                if (count == 0) return 0;
                int startIndex = (int)(m_read % m_intbuf.Length);
                int round1 = Math.Min(count, m_intbuf.Length - startIndex);
                Array.Copy(m_intbuf, startIndex, buffer, offset, round1);
                if (count > round1)
                    Array.Copy(m_intbuf, 0, buffer, offset + round1, count - round1);
                m_read += count;
                return count;
            }

            /// <summary> Returns count bytes from the very end of internal buffer. </summary>
            private byte[] peekLastBytesFromIntBuf(int count)
            {
                count = Math.Min(count, (int)(m_written - m_read));
                byte[] retBytes = new byte[count];
                long save_curpos = m_read;
                m_read = m_written - count;
                readFromIntBuf(retBytes, 0, count);
                m_read = save_curpos;
                return retBytes;
            }


            /// <summary>
            /// The overridden read function that ensures that the caller cannot see the hidden bytes
            /// </summary>
            /// <param name="buffer">The buffer to read into</param>
            /// <param name="offset">The offset into the buffer</param>
            /// <param name="count">The number of bytes to read</param>
            /// <returns>The number of bytes read</returns>
            public override int Read(byte[] buffer, int offset, int count)
            {
                if (m_intbuf == null) initIntBuf();

                int bufFilled = (int)(m_written - m_read);
                int bytesRead = 0;

                if (count <= 0 || (m_eof && bufFilled <= m_hiddenByteCount)) return 0;

                if (bufFilled > m_hiddenByteCount) // enough data available to return something
                {
                    bytesRead = Math.Min(bufFilled - m_hiddenByteCount, count);
                    bytesRead = readFromIntBuf(buffer, offset, bytesRead);
                    count -= bytesRead;
                    offset += bytesRead;
                }

                if (count > 0)
                {
                    int cnt = readToIntBuf(m_stream);
                    if (cnt == 0)
                    {
                        // to keep the hidden bytes available after Close, we copy to a small buffer
                        count = 0; m_eof = true;
                        m_finalHiddenBytes = peekLastBytesFromIntBuf(m_hiddenByteCount);
                    }
                    else bytesRead += readFromIntBuf(buffer, offset, Math.Min(count, cnt));
                }
                return bytesRead;
            }

            protected override void Dispose(bool disposing)
            {
                if (this.m_intbuf != null) this.m_intbuf = null;
                if (this.m_stream != null) this.m_stream = null; // no dispose of base stream, main class does this.
                base.Dispose(disposing);
            }
        }

        /// <summary>
        /// Helper function. Either reads to end (return value smaller <code>count</code>)
        /// or reads all <code>count</code> bytes.
        /// </summary>
        internal static int ForceRead(Stream stream, byte[] buf, int offset, int count)
        {
            int org_Count = count;
            int c;
            while (count > 0 && (c = stream.Read(buf, offset, count)) != 0)
            { count -= c; offset += c; }
            return (org_Count - count);
        }

        /// <summary>
        /// Helper function to support reading from streams that chunck data.
        /// Will keep reading a stream until <paramref name="count"/> bytes have been read.
        /// Throws an exception if the stream is exhausted before <paramref name="count"/> bytes are read.
        /// </summary>
        /// <param name="stream">The stream to read from</param>
        /// <param name="count">The number of bytes to read</param>
        /// <returns>The data read</returns>
        internal static byte[] RepeatRead(Stream stream, int count)
        {
            byte[] tmp = new byte[count];
            if (ForceRead(stream, tmp, 0, count) < count)
                throw new InvalidDataException(Strings.UnexpectedEndOfStream);
            return tmp;
        }

        #endregion

        #region Public exceptions to signal certain errors

        /// <summary> An exception raised to signal a hash mismatch on decryption </summary>
        [Serializable]
        public class HashMismatchException :  CryptographicException
        {
			/// <summary>
			/// Initializes a new instance of the HashMismatchException class.
			/// </summary>
			/// <param name="message">The error message to report.</param>
            public HashMismatchException(string message) : base(message) { }
        }

        /// <summary> An exception raised to signal that a wrong password was used </summary>
        [Serializable]
        public class WrongPasswordException : CryptographicException
        {
			/// <summary>
			/// Initializes a new instance of the WrongPasswordException class.
			/// </summary>
			/// <param name="message">The error message to report.</param>
            public WrongPasswordException(string message) : base(message) { }
        }

        #endregion

        #region Public static API

        #region Default extension control variables
        /// <summary>
        /// The name inserted as the creator software in the extensions when creating output
        /// </summary>
        public static string Extension_CreatedByIdentifier = string.Format("SharpAESCrypt v{0}", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);

        /// <summary>
        /// A value indicating if the extension data should contain the creator software
        /// </summary>
        public static bool Extension_InsertCreateByIdentifier = true;

        /// <summary>
        /// A value indicating if the extensions data should contain timestamp data
        /// </summary>
        public static bool Extension_InsertTimeStamp = false;

        /// <summary>
        /// A value indicating if the extensions data should contain an empty block as suggested by the file format
        /// </summary>
        public static bool Extension_InsertPlaceholder = true;
        #endregion

        /// <summary>
        /// The file version to use when creating a new file
        /// </summary>
        public static byte DefaultFileVersion = MAX_FILE_VERSION;

        /// <summary>
        /// Encrypts a stream using the supplied password
        /// </summary>
        /// <param name="password">The password to decrypt with</param>
        /// <param name="input">The stream with unencrypted data</param>
        /// <param name="output">The encrypted output stream</param>
        /// <param name="maxThreads">Maximum threads allowed for SharpAESCrypt. </param>
        public static void Encrypt(string password, Stream input, Stream output, int maxThreads = DEFAULT_THREADS)
        {
            int a;
            byte[] buffer = new byte[1024 * 4];
            SharpAESCrypt c = new SharpAESCrypt(password, output, OperationMode.Encrypt);
            if (maxThreads > 0) c.MaxCryptoThreads = maxThreads;
            while ((a = input.Read(buffer, 0, buffer.Length)) != 0)
                c.Write(buffer, 0, a);
            c.FlushFinalBlock();
        }

        /// <summary>
        /// Decrypts a stream using the supplied password
        /// </summary>
        /// <param name="password">The password to encrypt with</param>
        /// <param name="input">The stream with encrypted data</param>
        /// <param name="output">The unencrypted output stream</param>
		/// <param name="skipFileSizeCheck"><c>True</c> if the file-size check should be ignored, <c>false</c> otherwise. Only use this for error recovery modes</param>
        /// <param name="maxThreads">Maximum threads allowed for SharpAESCrypt. </param>
        public static void Decrypt(string password, Stream input, Stream output, bool skipFileSizeCheck = false, int maxThreads = DEFAULT_THREADS)
        {
            int a;
            byte[] buffer = new byte[1024 * 4];

            SharpAESCrypt c = new SharpAESCrypt(password, input, OperationMode.Decrypt, skipFileSizeCheck);
            if (maxThreads > 0) c.MaxCryptoThreads = maxThreads;
            while ((a = c.Read(buffer, 0, buffer.Length)) != 0)
                output.Write(buffer, 0, a);
        }

        /// <summary>
        /// Encrypts a file using the supplied password
        /// </summary>
        /// <param name="password">The password to encrypt with</param>
        /// <param name="inputfile">The file with unencrypted data</param>
        /// <param name="outputfile">The encrypted output file</param>
        /// <param name="maxThreads">Maximum threads allowed for SharpAESCrypt. </param>
        public static void Encrypt(string password, string inputfile, string outputfile, int maxThreads = DEFAULT_THREADS)
        {
            using (FileStream infs = File.OpenRead(inputfile))
            using (FileStream outfs = File.Create(outputfile))
                Encrypt(password, infs, outfs, maxThreads);
        }

        /// <summary>
        /// Decrypts a file using the supplied password
        /// </summary>
        /// <param name="password">The password to decrypt with</param>
        /// <param name="inputfile">The file with encrypted data</param>
        /// <param name="outputfile">The unencrypted output file</param>
		/// <param name="skipFileSizeCheck"><c>True</c> if the file-size check should be ignored, <c>false</c> otherwise. Only use this for error recovery modes</param>
        /// <param name="maxThreads">Maximum threads allowed for SharpAESCrypt. </param>
        public static void Decrypt(string password, string inputfile, string outputfile, bool skipFileSizeCheck = false, int maxThreads = DEFAULT_THREADS)
        {
            using (FileStream infs = File.OpenRead(inputfile))
            using (FileStream outfs = File.Create(outputfile))
                Decrypt(password, infs, outfs, skipFileSizeCheck, maxThreads);
        }
        #endregion

        #region Public instance API

        /// <summary>
        /// Constructs a new AESCrypt instance, operating on the supplied stream
        /// </summary>
        /// <param name="password">The password used for encryption or decryption</param>
        /// <param name="stream">The stream to operate on, must be writeable for encryption, and readable for decryption</param>
        /// <param name="mode">The mode of operation, either OperationMode.Encrypt or OperationMode.Decrypt</param>
        /// <param name="skipFileSizeCheck">Skip file size check on seekable streams. For disaster recovery. </param>
        public SharpAESCrypt(string password, Stream stream, OperationMode mode, bool skipFileSizeCheck = false)
        {
            //Basic input checks
            if (stream == null)
                throw new ArgumentNullException("stream");
            if (password == null)
                throw new ArgumentNullException("password");
            if (mode != OperationMode.Encrypt && mode != OperationMode.Decrypt)
                throw new ArgumentException(Strings.InvalidOperationMode, "mode");
            if (mode == OperationMode.Encrypt && !stream.CanWrite)
                throw new ArgumentException(Strings.StreamMustBeWriteAble, "stream");
            if (mode == OperationMode.Decrypt && !stream.CanRead)
                throw new ArgumentException(Strings.StreamMustBeReadAble, "stream");

            m_mode = mode;
            m_stream = stream;
            m_extensions = new List<KeyValuePair<string, byte[]>>();

            if (mode == OperationMode.Encrypt)
            {
                this.Version = DefaultFileVersion;

                m_helper = new SetupHelper(mode, password, null);

                //Setup default extensions
                if (Extension_InsertCreateByIdentifier)
                    m_extensions.Add(new KeyValuePair<string, byte[]>("CREATED_BY", System.Text.Encoding.UTF8.GetBytes(Extension_CreatedByIdentifier)));

                if (Extension_InsertTimeStamp)
                {
                    m_extensions.Add(new KeyValuePair<string, byte[]>("CREATED_DATE", System.Text.Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyy-MM-dd"))));
                    m_extensions.Add(new KeyValuePair<string, byte[]>("CREATED_TIME", System.Text.Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("hh-mm-ss"))));
                }

                if (Extension_InsertPlaceholder)
                    m_extensions.Add(new KeyValuePair<string, byte[]>(String.Empty, new byte[127])); //Suggested extension space

                //We defer creation of the cryptostream until it is needed, 
                // so the caller can change version, extensions, etc. 
                // before we write the header
                m_cryptDataStream = null;
            }
            else
            {
                //Read and validate
                ReadEncryptionHeader(password, skipFileSizeCheck);

                // We defer creation of the cryptostream until it is needed, 
                // so the caller can change some behaviour properties 
                // before decryption starts (e.g. for threading).
                m_cryptDataStream = null;
            }
        }


        /// <summary>
        /// Gets or sets the version number.
        /// Note that this can only be set when encrypting, 
        /// and must be done before encryption has started.
        /// See <value>MAX_FILE_VERSION</value> for the maximum supported version.
        /// Note that version 0 requires a seekable stream.
        /// </summary>
        public byte Version
        {
            get { return m_version; }
            set
            {
                if (m_mode == OperationMode.Decrypt)
                    throw new InvalidOperationException(Strings.VersionReadonlyForDecryption);
                if (m_mode == OperationMode.Encrypt && m_cryptDataStream != null)
                    throw new InvalidOperationException(Strings.VersionReadonly);
                if (value > MAX_FILE_VERSION)
                    throw new ArgumentOutOfRangeException(string.Format(Strings.VersionUnsupported, MAX_FILE_VERSION));
                if (value == 0 && !m_stream.CanSeek)
                    throw new InvalidOperationException(Strings.StreamMustSupportSeeking);

                m_version = value;
            }
        }

        /// <summary>
        /// Gets or sets how many threads may be used for crypto-operation.
        /// 1 is single thread, 2 dual threads to decouple hashing,
        /// > 2 multithreads aes (decryption only).
        /// Note that this must be done before en-/decryption has started.
        /// </summary>
        public int MaxCryptoThreads
        {
            get { return m_maxCryptoThreads; }
            set
            {
                if (m_cryptDataStream != null)
                    throw new InvalidOperationException(Strings.ThreadingReadonly);
                m_maxCryptoThreads = value;
            }
        }


        /// <summary>
        /// Provides access to the extensions found in the file.
        /// This collection cannot be updated when decrypting, 
        /// nor after the encryption has started.
        /// </summary>
        public IList<KeyValuePair<string, byte[]>> Extensions
        {
            get
            {
                if (m_mode == OperationMode.Decrypt || (m_mode == OperationMode.Encrypt && m_cryptDataStream != null))
                    return m_extensions.AsReadOnly();
                else
                    return m_extensions;
            }
        }

        #region Basic stream implementation stuff, all mapped directly to the cryptostream
        /// <summary>
        /// Gets a value indicating whether this instance can read.
        /// </summary>
        /// <value><c>true</c> if this instance can read; otherwise, <c>false</c>.</value>
        public override bool CanRead { get { return Crypto.CanRead; } }
        /// <summary>
        /// Gets a value indicating whether this instance can seek.
        /// </summary>
        /// <value><c>true</c> if this instance can seek; otherwise, <c>false</c>.</value>
        public override bool CanSeek { get { return Crypto.CanSeek; } }
        /// <summary>
        /// Gets a value indicating whether this instance can write.
        /// </summary>
        /// <value><c>true</c> if this instance can write; otherwise, <c>false</c>.</value>
        public override bool CanWrite { get { return Crypto.CanWrite; } }
        /// <Docs>An I/O error occurs.</Docs>
        /// <summary>
        /// Flush this instance.
        /// </summary>
        public override void Flush() { Crypto.Flush(); }
        /// <summary>
        /// Gets the length.
        /// </summary>
        /// <value>The length.</value>
        public override long Length { get { return Crypto.Length; } }
        /// <summary>
        /// Gets or sets the position.
        /// </summary>
        /// <value>The position.</value>
        public override long Position
        {
            get { return Crypto.Position; }
            set { Crypto.Position = value; }
        }
        /// <Docs>The stream does not support seeking, such as if the stream is constructed from a pipe or console output.</Docs>
        /// <exception cref="T:System.IO.IOException">An I/O error has occurred.</exception>
        /// <attribution license="cc4" from="Microsoft" modified="false"></attribution>
        /// <see cref="P:System.IO.Stream.CanSeek"></see>
        /// <summary>
        /// Seek the specified offset and origin.
        /// </summary>
        /// <param name="offset">Offset.</param>
        /// <param name="origin">Origin.</param>
        public override long Seek(long offset, System.IO.SeekOrigin origin) { return Crypto.Seek(offset, origin); }
        /// <Docs>The stream does not support both writing and seeking, such as if the stream is constructed from a pipe or
        /// console output.</Docs>
        /// <exception cref="T:System.IO.IOException">An I/O error occurred.</exception>
        /// <attribution license="cc4" from="Microsoft" modified="false"></attribution>
        /// <para>A stream must support both writing and seeking for SetLength to work.</para>
        /// <see cref="P:System.IO.Stream.CanWrite"></see>
        /// <see cref="P:System.IO.Stream.CanSeek"></see>
        /// <summary>
        /// Sets the length.
        /// </summary>
        /// <param name="value">Value.</param>
        public override void SetLength(long value) { Crypto.SetLength(value); }
        #endregion

        /// <summary>
        /// Reads unencrypted data from the underlying stream
        /// </summary>
        /// <param name="buffer">The buffer to read data into</param>
        /// <param name="offset">The offset into the buffer</param>
        /// <param name="count">The number of bytes to read</param>
        /// <returns>The number of bytes read</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (m_mode != OperationMode.Decrypt)
                throw new InvalidOperationException(Strings.CannotReadWhileEncrypting);

            if ((m_hasReadFooter && m_curBlockBytes == 0) || count == 0)
                return 0;

            bool isInit = false;
            bool isEOF = false;
            int bytesRead = 0;

            if (!m_hasReadFooter && m_nextBlock == null) // init buffers for read ahead (needed for padding)
            {
                isInit = true;
                m_curBlockBytes = 0;
                m_nextBlock = new byte[BLOCK_SIZE];
                m_curBlock = new byte[BLOCK_SIZE];
            }

            if (m_curBlockBytes > 0) // flush current buffer to reader
            {
                int c = Math.Min(count, m_curBlockBytes);
                Array.Copy(m_curBlock, BLOCK_SIZE - m_curBlockBytes, buffer, offset, c);
                bytesRead += c;
                m_curBlockBytes -= bytesRead;
                count -= bytesRead;
                offset += bytesRead;
            }

            try
            {
                if (!m_hasReadFooter && count > 0)
                {
                    if (count >= 2 * BLOCK_SIZE)
                    {
                        count = count - (count % BLOCK_SIZE);
                        int prependBlock = isInit ? 0 : BLOCK_SIZE;

                        int read = ForceRead(Crypto, buffer, offset + prependBlock, count - prependBlock);
                        m_readcount += read;

                        if (read % BLOCK_SIZE != 0) throw new InvalidDataException(Strings.UnexpectedEndOfStream);

                        if (read > 0)
                        {
                            Array.Copy(m_nextBlock, 0, buffer, offset, prependBlock);
                            bytesRead += prependBlock;
                            offset += prependBlock; count -= prependBlock;
                            Array.Copy(buffer, offset + read - BLOCK_SIZE, m_nextBlock, 0, BLOCK_SIZE);
                            bytesRead += read - BLOCK_SIZE;
                            offset += read - BLOCK_SIZE;
                            count -= read - BLOCK_SIZE;
                        }
                        else if (isInit) m_nextBlock = null; // empty stream, no next block

                        isEOF = (read < count);
                    }
                    else if (bytesRead == 0) // otherwise simply return current chunk
                    {
                        // read single next block and switch buffers
                        int read = ForceRead(Crypto, m_curBlock, 0, BLOCK_SIZE);
                        m_readcount += read;
                        if (read % BLOCK_SIZE != 0) throw new InvalidDataException(Strings.UnexpectedEndOfStream);

                        if (isInit) // read first next block
                        {
                            if (read == 0) { m_nextBlock = null; } // empty stream, no next block
                            else
                            {
                                byte[] t = m_curBlock; m_curBlock = m_nextBlock; m_nextBlock = t;
                                read = ForceRead(Crypto, m_curBlock, 0, BLOCK_SIZE);
                                m_readcount += read;
                                if (read % BLOCK_SIZE != 0) throw new InvalidDataException(Strings.UnexpectedEndOfStream);
                            }
                        }

                        if (read > 0)
                        {
                            byte[] t = m_curBlock; m_curBlock = m_nextBlock; m_nextBlock = t;

                            m_curBlockBytes = BLOCK_SIZE;
                            int c = Math.Min(count, m_curBlockBytes);
                            Array.Copy(m_curBlock, BLOCK_SIZE - m_curBlockBytes, buffer, offset, c);
                            bytesRead += c;
                            m_curBlockBytes -= c;
                            offset += c;
                            count -= c;
                        }
                        else isEOF = true;
                    }
                }
            }
            catch // on exception, close Crypto so threads end in multi-threading. No recovery possible.
            {
                Crypto.Close();
                throw;
            }

            //TODO: If the cryptostream supporting seeking in future versions of .Net, 
            // this counter system does not work

            if (!m_hasReadFooter && isEOF)
            {
                // First thing, close Crypto-stream and synch, before accessing hash values
                Crypto.Close();

                if (m_cryptoThreadPump != null)
                {
                    m_cryptoThreadPump.WaitHandle.WaitOne();
                    // If there was an exception (e.g. EOF in base stream) we rethrow
                    if (m_cryptoThreadPump.Exception != null)
                        throw m_cryptoThreadPump.Exception;
                }

                m_hasReadFooter = true;

                if (m_payloadStream.PayloadLength < 0)
                    throw new InvalidDataException(Strings.UnexpectedEndOfStream);
                else if (m_payloadStream.PayloadLength % BLOCK_SIZE != 0)
                    throw new InvalidDataException(Strings.InvalidFileLength);
                else if (m_payloadStream.PayloadLength != m_readcount)
                    throw new InvalidDataException(Strings.StreamSizeMismatch );

                int hMacOffset = 0;

                //Verify the data
                if (m_version >= 1)
                {
                    int l = m_payloadStream.GetHiddenBytes(0, 1)[0];
                    hMacOffset++;
                    if (l < 0)
                        throw new InvalidDataException(Strings.UnexpectedEndOfStream);
                    m_paddingSize = (byte)l;
                    if (m_paddingSize > BLOCK_SIZE)
                        throw new InvalidDataException(Strings.InvalidFileLength);
                }

                if (m_readcount % BLOCK_SIZE != 0)
                    throw new InvalidDataException(Strings.InvalidFileLength);

                //Required because we want to read the hash, 
                // so FlushFinalBlock need to be called.
                //We cannot call FlushFinalBlock directly because it may
                // have been called by the read operation.

                byte[] hmac2 = m_payloadStream.GetHiddenBytes(hMacOffset, m_hmac.HashSize / 8);

                byte[] hmac1 = m_hmac.Hash;
                for (int i = 0; i < hmac1.Length; i++)
                    if (hmac1[i] != hmac2[i])
                        throw new HashMismatchException(m_version == 0 ? Strings.DataHMACMismatch_v0 : Strings.DataHMACMismatch);
            }

            // Flush final un-padded block to caller
            if (m_hasReadFooter && m_curBlockBytes == 0 && m_nextBlock != null)
            {
                m_curBlockBytes = m_paddingSize == 0 ? BLOCK_SIZE : m_paddingSize;
                Array.Copy(m_nextBlock, 0, m_curBlock, BLOCK_SIZE - m_curBlockBytes, m_curBlockBytes);
                m_nextBlock = null;
                int c = Math.Min(count, m_curBlockBytes);
                Array.Copy(m_curBlock, BLOCK_SIZE - m_curBlockBytes, buffer, offset, c);
                bytesRead += c;
                m_curBlockBytes -= c;
                offset += c;
                count -= c;
            }

            return bytesRead;
        }

        /// <summary>
        /// Writes unencrypted data into an encrypted stream
        /// </summary>
        /// <param name="buffer">The data to write</param>
        /// <param name="offset">The offset into the buffer</param>
        /// <param name="count">The number of bytes to write</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            try
            {
                if (m_mode != OperationMode.Encrypt)
                    throw new InvalidOperationException(Strings.CannotWriteWhileDecrypting);

                m_length = (m_length + count) % BLOCK_SIZE;
                Crypto.Write(buffer, offset, count);
            }
            catch // on exception, close Crypto so threads end in multi-threading. No recovery possible.
            {
                Crypto.Close();
                m_hasFlushedFinalBlock = true;
                throw;
            }

        }

        /// <summary>
        /// Flushes any remaining data to the stream
        /// </summary>
        public void FlushFinalBlock()
        {
            if (!m_hasFlushedFinalBlock)
            {
                if (m_mode == OperationMode.Encrypt)
                {
                    try
                    {
                        // Dummy access to make sure the header is written.
                        Crypto.Write(new byte[0], 0, 0);

                        byte lastLen = (byte)(m_length %= BLOCK_SIZE);

                        //Apply PaddingMode.PKCS7 manually, the original AES crypt uses non-standard padding
                        if (lastLen != 0)
                        {
                            byte[] padding = new byte[BLOCK_SIZE - lastLen];
                            for (int i = 0; i < padding.Length; i++)
                                padding[i] = (byte)padding.Length;
                            Write(padding, 0, padding.Length);
                        }

                        // Not required without padding, but might throw exception if the stream is used incorrectly
                        Stream crypto = Crypto;
                        if (crypto is CryptoStream)
                            ((CryptoStream)crypto).FlushFinalBlock();

                        // The LeaveOpenStrem makes sure the underlying m_stream is not closed.
                        // All other streams are automatically closed.
                        Crypto.Close();

                        if (m_cryptoThreadPump != null) // Synchronize and check for exceptions
                        {
                            m_cryptoThreadPump.WaitHandle.WaitOne();
                            if (m_cryptoThreadPump.Exception != null) throw m_cryptoThreadPump.Exception;
                        }

                        byte[] hmac = m_hmac.Hash;

                        if (m_version == 0)
                        {
                            m_stream.Write(hmac, 0, hmac.Length);
                            long pos = m_stream.Position;
                            m_stream.Seek(MAGIC_HEADER.Length + 1, SeekOrigin.Begin);
                            m_stream.WriteByte(lastLen);
                            m_stream.Seek(pos, SeekOrigin.Begin);
                            m_stream.Flush();
                        }
                        else
                        {
                            m_stream.WriteByte(lastLen);
                            m_stream.Write(hmac, 0, hmac.Length);
                            m_stream.Flush();
                        }
                    }
                    catch // on exception, close Crypto so threads end in multi-threading. No recovery possible.
                    {
                        Crypto.Close();
                        throw;
                    }
                }
                m_hasFlushedFinalBlock = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the instance, and flushes any data currently held, into the stream
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                if (m_mode == OperationMode.Encrypt && !m_hasFlushedFinalBlock)
                    FlushFinalBlock();

                if (m_cryptDataStream != null)
                    m_cryptDataStream.Dispose();
                m_cryptDataStream = null;

                if (m_stream != null)
                    m_stream.Dispose();
                m_stream = null;
                m_extensions = null;
                if (m_helper != null)
                    m_helper.Dispose();
                m_helper = null;
                m_hmac = null;
            }
        }

        #endregion

#if !IsLibrary
        /// <summary>
        /// Main function, used when compiled as a standalone executable
        /// </summary>
        /// <param name="args">Commandline arguments</param>
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Environment.ExitCode = 1;
                Console.Error.WriteLine(Strings.CommandlineUsage);
                return;
            }

            bool encrypt = args[0].StartsWith("e", StringComparison.InvariantCultureIgnoreCase);
            bool decrypt = args[0].StartsWith("d", StringComparison.InvariantCultureIgnoreCase);
            bool optimisticMode = (args[0].IndexOf("o", StringComparison.InvariantCultureIgnoreCase) >= 0);

            int maxThreads = 1;
            for (int testFor = 1; testFor <= 4; testFor++)
                if (args[0].IndexOf((char)('0' + testFor)) >= 0) maxThreads = testFor;

            if (!(encrypt || decrypt))
            {
                Environment.ExitCode = 1;
                Console.Error.WriteLine(Strings.CommandlineUnknownMode);
                return;
            }

            string inputname = (args.Length >= 3) ? args[2] : null;
            string outputname = (args.Length >= 4) ? args[3] : null;

            if (inputname != null && !File.Exists(inputname))
            {
                Environment.ExitCode = 2;
                Console.Error.WriteLine(Strings.CommandlineInputFileNotFound);
                return;
            }


            try
            {
#if DEBUG
                DateTime start = DateTime.Now;
#endif

                using (Stream inputstream = (inputname != null) ? File.OpenRead(inputname) : Console.OpenStandardInput())
                using (Stream outputstream = (outputname != null) ? File.Create(outputname) : Console.OpenStandardOutput())
                    if (encrypt)
                        Encrypt(args[1], inputstream, outputstream, maxThreads);
                    else
                        Decrypt(args[1], inputstream, outputstream, optimisticMode, maxThreads);
                Environment.ExitCode = 0;

#if DEBUG
                TimeSpan dur = (DateTime.Now - start);
                if (outputname != null) Console.WriteLine("Done! Crypting took about {0:0} ms", dur.TotalMilliseconds);
#endif

            }
            catch (Exception ex)
            {
                if (ex is WrongPasswordException)
                    Environment.ExitCode = 4;
                if (ex is HashMismatchException)
                    Environment.ExitCode = 3;
                else
                    Environment.ExitCode = 1;

                Console.Error.WriteLine(string.Format(Strings.CommandlineError, ex.Message));
                // Delete output file if something went wrong
                if (!optimisticMode && outputname != null)
                {
                    try { File.Delete(outputname); }
                    catch { }
                }
            }
        }
#endif
    }

}
