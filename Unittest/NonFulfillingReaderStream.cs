using System;
using System.IO;

namespace SharpAESCrypt.Unittest
{
    public class NonFulfillingReaderStream : Stream
    {
        private Stream m_source;
        private Random m_random;
        public NonFulfillingReaderStream(Stream source)
        {
            m_source = source;
            m_random = new Random();
        }

        #region implemented abstract members of Stream

        public override void Flush() { m_source.Flush(); }
        public override long Seek(long offset, SeekOrigin origin) { return m_source.Seek(offset, origin); }
        public override void SetLength(long value) { m_source.SetLength(value); }
        public override void Write(byte[] buffer, int offset, int count) { m_source.Write(buffer, offset, count); }
        public override bool CanRead { get { return m_source.CanRead; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return m_source.CanWrite; } }
        public override long Length { get { return m_source.Length; } }
        public override long Position
        {
            get { return m_source.Position; }
            set { m_source.Position = value; }
        }

        public override int Read(byte[] buffer, int offset, int count) 
        {
            if (count == 0) return 0;
            int c = m_random.Next(count) + 1;
            return m_source.Read(buffer, offset, c); 
        }

        #endregion
    }
}