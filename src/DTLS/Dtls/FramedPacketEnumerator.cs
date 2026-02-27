using System.Buffers.Binary;

namespace DTLS.Dtls;

/// <summary>Enumerates individual datagrams from [u16_le:len][bytes]... framed output.</summary>
internal ref struct FramedPacketEnumerator(ReadOnlySpan<byte> framed)
{
	private ReadOnlySpan<byte> _remaining = framed;

	public ReadOnlySpan<byte> Current { get; private set; }

	public bool MoveNext()
	{
		if (!BinaryPrimitives.TryReadUInt16LittleEndian(_remaining, out ushort len))
		{
			return false;
		}

		_remaining = _remaining.Slice(sizeof(ushort));

		if (len > _remaining.Length)
		{
			return false;
		}

		Current = _remaining.Slice(0, len);
		_remaining = _remaining.Slice(len);
		return true;
	}

	public FramedPacketEnumerator GetEnumerator()
	{
		return this;
	}
}
