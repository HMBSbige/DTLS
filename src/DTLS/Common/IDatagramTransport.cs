namespace DTLS.Common;

public interface IDatagramTransport
{
	/// <summary>Returns one complete datagram's byte count, or 0 when closed.</summary>
	/// <remarks>Datagrams must not be truncated.</remarks>
	ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);

	ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default);
}
