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
        public static string CommandlineUsage = "SharpAESCrypt e|d <password> [<fromPath>] [<toPath>]" +
            Environment.NewLine +
            Environment.NewLine +
            "If you ommit the fromPath or toPath, stdin/stdout are used insted, e.g.:" +
            Environment.NewLine +
            " SharpAESCrypt e 1234 < file.jpg > file.jpg.aes"
            ;

        /// <summary>
        /// A string displayed when an error occurs while running the commandline program
        /// </summary>
        public static string CommandlineError = "Error: {0}";
        /// <summary>
        /// A string displayed if the mode is neither e nor d 
        /// </summary>
        public static string CommandlineUnknownMode = "Invalid operation, must be (e)ncrypt or (d)ecrypt";
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
        private const int BLOCK_SIZE = 16;
        /// <summary>
        /// The size of the IV, in bytes, which is the same as the blocksize for AES
        /// </summary>
        private const int IV_SIZE = 16;
        /// <summary>
        /// The size of the key. For AES-256 that is 256/8 = 32
        /// </summary>
        private const int KEY_SIZE = 32;
        /// <summary>
        /// The size of the SHA-256 output, which matches the KEY_SIZE
        /// </summary>
        private const int HASH_SIZE = 32;
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
        /// The cryptostream used to perform bulk encryption
        /// </summary>
        private CryptoStream m_crypto;
        /// <summary>
        /// Helper payload stream for decryption
        /// </summary>
        private StreamHider m_payloadStream;
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
        /// True if the header is written, false otherwise. Used only for encryption.
        /// </summary>
        private bool m_hasWrittenHeader = false;
        /// <summary>
        /// True if the footer has been written, false otherwise. Used only for encryption.
        /// </summary>
        private bool m_hasFlushedFinalBlock = false;
        /// <summary>
        /// The size of the payload, including padding. Used only for decryption.
        /// </summary>
        private long m_payloadLength;
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
        private CryptoStream Crypto
        {
            get
            {
                if (m_crypto == null)
                    WriteEncryptionHeader();
                return m_crypto;
            }
        }

        /// <summary>
        /// Helper function to read and validate the header
        /// </summary>
        private void ReadEncryptionHeader(string password)
        {
            byte[] tmp = new byte[MAGIC_HEADER.Length + 2];
            if (m_stream.Read(tmp, 0, tmp.Length) != tmp.Length)
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

            if (m_version >= 1)
            {
                byte[] hmac1 = m_helper.DecryptAESKey2(RepeatRead(m_stream, IV_SIZE + KEY_SIZE));
                byte[] hmac2 = RepeatRead(m_stream, hmac1.Length);
                for (int i = 0; i < hmac1.Length; i++)
                    if (hmac1[i] != hmac2[i])
                        throw new CryptographicException(Strings.InvalidPassword);

                if (m_stream.CanSeek)
                {
                    try { m_payloadLength = m_stream.Length - m_stream.Position - (HASH_SIZE + 1); }
                    catch { m_payloadLength = -1; }
                }
                else
                    m_payloadLength = -1;
            }
            else
            {
                m_helper.SetBulkKeyToKey1();

                if (m_stream.CanSeek)
                {
                    try { m_payloadLength = m_stream.Length - m_stream.Position - HASH_SIZE; }
                    catch { m_payloadLength = -1; }
                }
                else
                    m_payloadLength = -1;
            }

            if (m_payloadLength != -1 && (m_payloadLength % BLOCK_SIZE != 0))
                throw new CryptographicException(Strings.InvalidFileLength);
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

            m_hmac = m_helper.GetHMAC();

            //Insert the HMAC before the stream to calculate the HMAC for the ciphertext
            m_crypto = new CryptoStream(new CryptoStream(new LeavOpenStream(m_stream), m_hmac, CryptoStreamMode.Write), m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Write);
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
            /// The algorithm used to encrypt and decrypt data
            /// </summary>
            private const string CRYPT_ALGORITHM = "Rijndael";

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
            /// Initialize the setup
            /// </summary>
            /// <param name="mode">The mode to prepare for</param>
            /// <param name="password">The password used to encrypt or decrypt</param>
            /// <param name="iv">The IV used, set to null if encrypting</param>
            public SetupHelper(OperationMode mode, string password, byte[] iv)
            {
                m_crypt = SymmetricAlgorithm.Create(CRYPT_ALGORITHM);

                //Not sure how to insert this with the CRYPT_ALGORITHM string
                m_crypt.Padding = PaddingMode.None;
                m_crypt.Mode = CipherMode.CBC;

                m_hash = HashAlgorithm.Create(HASH_ALGORITHM);
                m_rand = RandomNumberGenerator.Create(/*RAND_ALGORITHM*/);
                m_hmac = HMAC.Create(HMAC_ALGORITHM);

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
                HMAC h = HMAC.Create(HMAC_ALGORITHM);
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
        /// Internal helper class, used to prevent a overlay stream from closing its base
        /// </summary>
        private class LeavOpenStream : Stream
        {
            /// <summary> The wrapped stream </summary>
            private Stream m_stream;

            public LeavOpenStream(Stream stream)
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
                while ((c = m_stream.Read(m_intbuf, bytesRead, m_bufsize)) != 0)
                { bytesRead += c; if (bytesRead >= m_hiddenByteCount) break; }
                m_written += bytesRead;
                m_eof = (c == 0);
            }

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
                    if (m_written < m_hiddenByteCount)
                        throw new IOException(Strings.UnexpectedEndOfStream);

                    if (count < 0 || offset < 0 || count + offset > m_hiddenByteCount)
                        throw new ArgumentException();

                    m_read = m_written - m_hiddenByteCount;
                    m_read += offset;
                    byte[] retBytes = new byte[count];
                    readFromIntBuf(retBytes, 0, count);
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
                int bufFree = m_intbuf.Length - bufFilled;
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
                    if (cnt == 0) { count = 0; m_eof = true; }
                    else bytesRead += readFromIntBuf(buffer, offset, Math.Min(count, cnt));
                }
                return bytesRead;
            }

            protected override void Dispose(bool disposing)
            {
                if (this.m_intbuf != null) this.m_intbuf = null;
                if (this.m_stream != null) {this.m_stream.Dispose(); this.m_stream = null;}
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
            while ((c = stream.Read(buf, offset, count)) != 0)
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
        public static void Encrypt(string password, Stream input, Stream output)
        {
            int a;
            byte[] buffer = new byte[1024 * 4];
            SharpAESCrypt c = new SharpAESCrypt(password, output, OperationMode.Encrypt);
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
        public static void Decrypt(string password, Stream input, Stream output)
        {
            int a;
            byte[] buffer = new byte[1024 * 4];
            SharpAESCrypt c = new SharpAESCrypt(password, input, OperationMode.Decrypt);
            while ((a = c.Read(buffer, 0, buffer.Length)) != 0)
                output.Write(buffer, 0, a);
        }

        /// <summary>
        /// Encrypts a file using the supplied password
        /// </summary>
        /// <param name="password">The password to encrypt with</param>
        /// <param name="inputfile">The file with unencrypted data</param>
        /// <param name="outputfile">The encrypted output file</param>
        public static void Encrypt(string password, string inputfile, string outputfile)
        {
            using (FileStream infs = File.OpenRead(inputfile))
            using (FileStream outfs = File.Create(outputfile))
                Encrypt(password, infs, outfs);
        }

        /// <summary>
        /// Decrypts a file using the supplied password
        /// </summary>
        /// <param name="password">The password to decrypt with</param>
        /// <param name="inputfile">The file with encrypted data</param>
        /// <param name="outputfile">The unencrypted output file</param>
        public static void Decrypt(string password, string inputfile, string outputfile)
        {
            using (FileStream infs = File.OpenRead(inputfile))
            using (FileStream outfs = File.Create(outputfile))
                Decrypt(password, infs, outfs);
        }
        #endregion

        #region Public instance API
        /// <summary>
        /// Constructs a new AESCrypt instance, operating on the supplied stream
        /// </summary>
        /// <param name="password">The password used for encryption or decryption</param>
        /// <param name="stream">The stream to operate on, must be writeable for encryption, and readable for decryption</param>
        /// <param name="mode">The mode of operation, either OperationMode.Encrypt or OperationMode.Decrypt</param>
        public SharpAESCrypt(string password, Stream stream, OperationMode mode)
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
                m_crypto = null;
            }
            else
            {
                //Read and validate
                ReadEncryptionHeader(password);

                m_hmac = m_helper.GetHMAC();

                //Insert the HMAC before the decryption so the HMAC is calculated for the ciphertext
                m_payloadStream = new StreamHider(m_stream, m_version == 0 ? HASH_SIZE : (HASH_SIZE + 1));
                m_crypto = new CryptoStream(new CryptoStream(m_payloadStream, m_hmac, CryptoStreamMode.Read), m_helper.CreateCryptoStream(m_mode), CryptoStreamMode.Read);
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
                if (m_mode == OperationMode.Encrypt && m_crypto != null)
                    throw new InvalidOperationException(Strings.VersionReadonly);
                if (value > MAX_FILE_VERSION)
                    throw new ArgumentOutOfRangeException(string.Format(Strings.VersionUnsupported, MAX_FILE_VERSION));
                if (value == 0 && !m_stream.CanSeek)
                    throw new InvalidOperationException(Strings.StreamMustSupportSeeking);

                m_version = value;
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
                if (m_mode == OperationMode.Decrypt || (m_mode == OperationMode.Encrypt && m_crypto != null))
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

            //TODO: If the cryptostream supporting seeking in future versions of .Net, 
            // this counter system does not work

            if (!m_hasReadFooter && isEOF)
            {
                m_hasReadFooter = true;

                if (m_payloadStream.PayloadLength != m_readcount)
                    throw new InvalidDataException(Strings.StreamSizeMismatch);

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
                Crypto.Close();

                byte[] hmac1 = m_hmac.Hash;
                for (int i = 0; i < hmac1.Length; i++)
                    if (hmac1[i] != hmac2[i])
                        throw new InvalidDataException(m_version == 0 ? Strings.DataHMACMismatch_v0 : Strings.DataHMACMismatch);
            }

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
            if (m_mode != OperationMode.Encrypt)
                throw new InvalidOperationException(Strings.CannotWriteWhileDecrypting);

            m_length = (m_length + count) % BLOCK_SIZE;
            Crypto.Write(buffer, offset, count);
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
                    if (!m_hasWrittenHeader)
                        WriteEncryptionHeader();

                    byte lastLen = (byte)(m_length %= BLOCK_SIZE);

                    //Apply PaddingMode.PKCS7 manually, the original AES crypt uses non-standard padding
                    if (lastLen != 0)
                    {
                        byte[] padding = new byte[BLOCK_SIZE - lastLen];
                        for (int i = 0; i < padding.Length; i++)
                            padding[i] = (byte)padding.Length;
                        Write(padding, 0, padding.Length);
                    }

                    //Not required without padding, but throws exception if the stream is used incorrectly
                    Crypto.FlushFinalBlock();
                    //The StreamHider makes sure the underlying stream is not closed.
                    Crypto.Close();

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

                if (m_crypto != null)
                    m_crypto.Dispose();
                m_crypto = null;

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

        /// <summary>
        /// Main function, used when compiled as a standalone executable
        /// </summary>
        /// <param name="args">Commandline arguments</param>
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine(Strings.CommandlineUsage);
                return;
            }

            bool encrypt = args[0].StartsWith("e", StringComparison.InvariantCultureIgnoreCase);
            bool decrypt = args[0].StartsWith("d", StringComparison.InvariantCultureIgnoreCase);
#if DEBUG

            if (args[0].StartsWith("u", StringComparison.InvariantCultureIgnoreCase))
            {
                Unittest();
                return;
            }
#endif

            if (!(encrypt || decrypt))
            {
                Console.WriteLine(Strings.CommandlineUsage);
                return;
            }

            try
            {
                using (Stream inputstream = args.Length >= 3 ? File.OpenRead(args[2]) : Console.OpenStandardInput())
                using (Stream outputstream = args.Length >= 4 ? File.Create(args[3]) : Console.OpenStandardOutput())
                    if (encrypt)
                        Encrypt(args[1], inputstream, outputstream);
                    else
                        Decrypt(args[1], inputstream, outputstream);
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format(Strings.CommandlineError, ex.ToString()));
            }
        }

        #region Unittest code
#if DEBUG
        /// <summary>
        /// Performs a unittest to ensure that the program performs as expected
        /// </summary>
        private static void Unittest()
        {
            const int MIN_SIZE = 1024 * 5;
            const int MAX_SIZE = 1024 * 1024 * 100; //100mb
            const int REPETIONS = 1000;

            bool allpass = true;

            Random rnd = new Random();
            Console.WriteLine("Running unittest");

            //Test each supported version
            for (byte v = 0; v <= MAX_FILE_VERSION; v++)
            {
                SharpAESCrypt.DefaultFileVersion = v;
                // Test at boundaries and around the block/keysize margins
                foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
                    for (int i = Math.Max(0, bound - 6 * BLOCK_SIZE - 1); i <= bound + (6 * BLOCK_SIZE + 1); i++)
                        using (MemoryStream ms = new MemoryStream())
                        {
                            byte[] tmp = new byte[i];
                            rnd.NextBytes(tmp);
                            ms.Write(tmp, 0, tmp.Length);
                            allpass &= Unittest(string.Format("Testing version {0} with length = {1} => ", v, ms.Length), ms, -1);
                        }
            }

            //Test each supported version with variavle buffer lengths
            for (byte v = 0; v <= MAX_FILE_VERSION; v++)
            {
                SharpAESCrypt.DefaultFileVersion = v;
                // Test at boundaries and around the block/keysize margins
                foreach (int bound in new int[] { 1 << 6, 1 << 8, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20 })
                    for (int i = Math.Max(0, bound - 6 * BLOCK_SIZE - 1); i <= bound + (6 * BLOCK_SIZE + 1); i++)
                        using (MemoryStream ms = new MemoryStream())
                        {
                            byte[] tmp = new byte[i];
                            rnd.NextBytes(tmp);
                            ms.Write(tmp, 0, tmp.Length);
                            allpass &= Unittest(string.Format("Testing version {0} with length = {1}, variable buffer sizes => ", v, ms.Length), ms, i + 3);
                        }
            }

            SharpAESCrypt.DefaultFileVersion = MAX_FILE_VERSION;
            Console.WriteLine(string.Format("Initial tests complete, running bulk tests with v{0}", SharpAESCrypt.DefaultFileVersion));

            for (int i = 0; i < REPETIONS; i++)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] tmp = new byte[rnd.Next(MIN_SIZE, MAX_SIZE)];
                    rnd.NextBytes(tmp);
                    ms.Write(tmp, 0, tmp.Length);
                    allpass |= Unittest(string.Format("Testing bulk {0} of {1} with length = {2} => ", i, REPETIONS, ms.Length), ms, 4096);
                }
            }

            {
                Console.WriteLine();
                Console.WriteLine();
                if (allpass)
                    Console.WriteLine("**** All unittests passed ****");
                else
                    Console.WriteLine("**** SOME TESTS FAILED !! ****");
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Helper function to perform a single test.
        /// </summary>
        /// <param name="message">A message printed to the console</param>
        /// <param name="input">The stream to test with</param>
        private static bool Unittest(string message, MemoryStream input, int useRndBufSize)
        {
            Console.Write(message);

            const string PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#¤%&/()=?`*'^¨-_.:,;<>|";
            const int MIN_LEN = 1;
            const int MAX_LEN = 25;

            try
            {
                Random rnd = new Random();
                char[] pwdchars = new char[rnd.Next(MIN_LEN, MAX_LEN)];
                for (int i = 0; i < pwdchars.Length; i++)
                    pwdchars[i] = PASSWORD_CHARS[rnd.Next(0, PASSWORD_CHARS.Length)];

                input.Position = 0;

                using (MemoryStream enc = new MemoryStream())
                using (MemoryStream dec = new MemoryStream())
                {
                    Encrypt(new string(pwdchars), input, enc);
                    enc.Position = 0;
                    if (useRndBufSize <= 0)
                        Decrypt(new string(pwdchars), enc, dec);
                    else
                        UnitStreamDecrypt(new string(pwdchars), enc, dec, useRndBufSize);

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
        private static void UnitStreamDecrypt(string password, Stream input, Stream output, int bufferSizeSelect)
        {
            Random r = new Random();

            int partBufs = Math.Min(bufferSizeSelect, 1024);

            byte[][] buffer = new byte[partBufs][];
            for (int bs = 1; bs < partBufs; bs++)
                buffer[bs] = new byte[bs];

            buffer[0] = new byte[bufferSizeSelect];

            int a;
            SharpAESCrypt c = new SharpAESCrypt(password, input, OperationMode.Decrypt);
            do
            {
                int bufLen = r.Next(bufferSizeSelect) + 1;
                byte[] useBuf = bufLen < partBufs ? buffer[bufLen] : buffer[0];
                a = c.Read(useBuf, 0, bufLen);
                output.Write(useBuf, 0, a);
            } while (a != 0);
        }

#endif
        #endregion
    }
}
