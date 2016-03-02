using System;
using System.IO;

namespace SharpAESCrypt.Unittest
{
	public class NonSeekableStream : Stream
	{
		private Stream m_source;
		public NonSeekableStream(Stream source)
		{
			m_source = source;
		}

		#region implemented abstract members of Stream

		public override void Flush() { m_source.Flush(); }
		public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException("Seeking not supported"); }
		public override void SetLength(long value) { throw new NotSupportedException("SetLength not supported"); }
		public override int Read(byte[] buffer, int offset, int count) { return m_source.Read(buffer, offset, count); }
		public override void Write(byte[] buffer, int offset, int count) { m_source.Write(buffer, offset, count); }
		public override bool CanRead { get { return m_source.CanRead; } }
		public override bool CanSeek { get { return false; } }
		public override bool CanWrite { get { return m_source.CanWrite; } }
		public override long Length 
		{
			get { throw new NotSupportedException("Length not supported"); } 
		}
		public override long Position 
		{
			get { throw new NotSupportedException("Position not supported"); }
			set { throw new NotSupportedException("Position not supported"); } 
		}

		#endregion
	}
}

