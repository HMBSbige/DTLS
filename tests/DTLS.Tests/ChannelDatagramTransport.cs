using DTLS.Common;
using System.Threading.Channels;

namespace DTLS.Tests;

internal sealed class ChannelDatagramTransport(ChannelReader<byte[]> reader, ChannelWriter<byte[]> writer) : IDatagramTransport
{
	public static (IDatagramTransport Client, IDatagramTransport Server) CreatePair()
	{
		Channel<byte[]> clientToServer = Channel.CreateUnbounded<byte[]>();
		Channel<byte[]> serverToClient = Channel.CreateUnbounded<byte[]>();
		return
		(
			new ChannelDatagramTransport(serverToClient.Reader, clientToServer.Writer),
			new ChannelDatagramTransport(clientToServer.Reader, serverToClient.Writer)
		);
	}

	public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		byte[] data = await reader.ReadAsync(cancellationToken);
		data.CopyTo(buffer);
		return data.Length;
	}

	public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		await writer.WriteAsync(datagram.ToArray(), cancellationToken);
	}
}
