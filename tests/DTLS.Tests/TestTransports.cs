using DTLS.Common;
using System.Net;
using System.Net.Sockets;

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

internal sealed class CountingTransport(IDatagramTransport inner) : IDatagramTransport
{
	private int _sendCount;

	public int SendCount => Volatile.Read(ref _sendCount);

	public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		return inner.ReceiveAsync(buffer, cancellationToken);
	}

	public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		Interlocked.Increment(ref _sendCount);
		return inner.SendAsync(datagram, cancellationToken);
	}
}

internal sealed class FailNextSendTransport(IDatagramTransport inner, Exception exception) : IDatagramTransport
{
	private int _armed;

	public void Arm()
	{
		Interlocked.Exchange(ref _armed, 1);
	}

	public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		return inner.ReceiveAsync(buffer, cancellationToken);
	}

	public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		if (Interlocked.CompareExchange(ref _armed, 0, 1) is 1)
		{
			return ValueTask.FromException(exception);
		}

		return inner.SendAsync(datagram, cancellationToken);
	}
}

internal sealed class ArmedSwapTransport(IDatagramTransport inner) : IDatagramTransport
{
	private readonly object _lock = new();
	private bool _armed;
	private byte[]? _held;

	public void Arm()
	{
		lock (_lock)
		{
			_armed = true;
		}
	}

	public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		return inner.ReceiveAsync(buffer, cancellationToken);
	}

	public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		byte[]? heldToFlush = null;

		lock (_lock)
		{
			if (_armed && _held is null)
			{
				_held = datagram.ToArray();
				return;
			}

			if (_armed && _held is not null)
			{
				heldToFlush = _held;
				_held = null;
				_armed = false;
			}
		}

		await inner.SendAsync(datagram, cancellationToken);

		if (heldToFlush is not null)
		{
			await inner.SendAsync(heldToFlush, cancellationToken);
		}
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
