using DTLS.Common;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace DTLS.Tests;

internal sealed class BlackHoleTransport : IDatagramTransport
{
	public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		await Task.Delay(Timeout.Infinite, cancellationToken);
		return 0;
	}

	public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		return ValueTask.CompletedTask;
	}
}

internal sealed class ChannelDatagramTransport(ChannelReader<byte[]> reader, ChannelWriter<byte[]> writer) : IDatagramTransport
{
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

internal sealed class ClosableTransport(IDatagramTransport inner) : IDatagramTransport
{
	private bool _closed;

	public void Close()
	{
		_closed = true;
	}

	public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		return _closed ? ValueTask.FromResult(0) : inner.ReceiveAsync(buffer, cancellationToken);
	}

	public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		return _closed ? ValueTask.CompletedTask : inner.SendAsync(datagram, cancellationToken);
	}
}

internal sealed class DropFirstSendTransport(IDatagramTransport inner) : IDatagramTransport
{
	private int _sendCount;

	public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		return inner.ReceiveAsync(buffer, cancellationToken);
	}

	public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		return Interlocked.Increment(ref _sendCount) is 1 ? ValueTask.CompletedTask : inner.SendAsync(datagram, cancellationToken);
	}
}

internal sealed class UdpDatagramTransport(UdpClient udp, IPEndPoint? remote = null) : IDatagramTransport
{
	private IPEndPoint? _remote = remote;

	public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		UdpReceiveResult result = await udp.ReceiveAsync(cancellationToken);
		_remote ??= result.RemoteEndPoint;
		result.Buffer.CopyTo(buffer);
		return result.Buffer.Length;
	}

	public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		await udp.SendAsync(datagram, _remote, cancellationToken);
	}
}
