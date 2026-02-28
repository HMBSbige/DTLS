using System.Buffers.Binary;

namespace DTLS.Dtls;

/// <summary>Enumerates individual datagrams from [u32_le:len][bytes]... framed output.</summary>
internal ref struct FramedPacketEnumerator(ReadOnlySpan<byte> framed)
{
	private ReadOnlySpan<byte> _remaining = framed;

	public ReadOnlySpan<byte> Current { get; private set; }

	public bool MoveNext()
	{
		if (!BinaryPrimitives.TryReadUInt32LittleEndian(_remaining, out uint len))
		{
			return false;
		}

		_remaining = _remaining.Slice(sizeof(uint));

		if (len > (uint)_remaining.Length)
		{
			return false;
		}

		Current = _remaining.Slice(0, (int)len);
		_remaining = _remaining.Slice((int)len);
		return true;
	}

	public FramedPacketEnumerator GetEnumerator()
	{
		return this;
	}
}
