namespace DTLS.Common;

/// <summary>
/// Low-level datagram transport abstraction for DTLS.
/// Preserves message boundaries (unlike <see cref="System.IO.Pipelines.IDuplexPipe"/>).
/// </summary>
public interface IDatagramTransport
{
	ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);
	ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default);
}
