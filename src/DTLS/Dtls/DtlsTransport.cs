using DTLS.Common;
using System.Buffers;
using System.Buffers.Binary;

namespace DTLS.Dtls;

/// <summary>
/// Async I/O wrapper over <see cref="DtlsSession"/>.
/// Bridges the sans-I/O protocol engine with an <see cref="IDatagramTransport"/>.
/// </summary>
public sealed class DtlsTransport : IDatagramTransport, IAsyncDisposable
{
	private const int IoBufferSize = 65536;
	private readonly IDatagramTransport _transport;
	private readonly TimeSpan _handshakeTimeout;
	private bool _disposed;

	public DtlsSession Session { get; }

	private DtlsTransport(DtlsSession session, IDatagramTransport transport, TimeSpan handshakeTimeout)
	{
		Session = session;
		_transport = transport;
		_handshakeTimeout = handshakeTimeout;
	}

	// ── Factory methods ──────────────────────────────────────

	public static async ValueTask<DtlsTransport> CreateClientAsync(IDatagramTransport transport, DtlsClientOptions options)
	{
		byte[] buf = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			(DtlsSession session, DtlsOpResult result) = DtlsSession.CreateClient(options, buf);
			await SendFramedAsync(transport, buf.AsMemory(0, result.BytesWritten));
			return new DtlsTransport(session, transport, options.HandshakeTimeout);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buf);
		}
	}

	public static async ValueTask<DtlsTransport> CreateServerAsync(IDatagramTransport transport, DtlsServerOptions options)
	{
		byte[] buf = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			(DtlsSession session, DtlsOpResult result) = DtlsSession.CreateServer(options, buf);
			await SendFramedAsync(transport, buf.AsMemory(0, result.BytesWritten));
			return new DtlsTransport(session, transport, options.HandshakeTimeout);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buf);
		}
	}

	// ── Handshake ────────────────────────────────────────────

	public async ValueTask HandshakeAsync(CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		cancellationTokenSource.CancelAfter(_handshakeTimeout);
		CancellationToken token = cancellationTokenSource.Token;

		byte[] buf = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			while (Session.IsHandshaking)
			{
				DtlsOpResult op;

				if (Session.TimeoutMs >= 0)
				{
					using CancellationTokenSource innerCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
					innerCancellationTokenSource.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(Session.TimeoutMs, 1)));

					try
					{
						op = Session.Feed(buf.AsSpan(0, await ReceiveOrThrow(buf, innerCancellationTokenSource.Token)), buf);
					}
					catch (OperationCanceledException) when (!token.IsCancellationRequested)
					{
						op = Session.HandleTimeout(buf);
					}
				}
				else
				{
					op = Session.Feed(buf.AsSpan(0, await ReceiveOrThrow(buf, token)), buf);
				}

				await SendFramedAsync(_transport, buf.AsMemory(0, op.BytesWritten), token);
			}
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			throw new DtlsTimeoutException("DTLS handshake timed out.");
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buf);
		}

		Session.VerifyPeer();
	}

	// ── IDatagramTransport ──────────────────────────────────

	public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		byte[] buf = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			DtlsOpResult op = Session.Send(datagram.Span, buf);
			await SendFramedAsync(_transport, buf.AsMemory(0, op.BytesWritten), cancellationToken);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buf);
		}
	}

	public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		byte[] buf = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			while (true)
			{
				DtlsOpResult r = Session.TryReceive(buffer.Span);

				if (r.BytesRead > 0)
				{
					return r.BytesRead;
				}

				int n = await _transport.ReceiveAsync(buf, cancellationToken);

				if (n is 0)
				{
					return 0;
				}

				DtlsOpResult op = Session.Feed(buf.AsSpan(0, n), buf);
				await SendFramedAsync(_transport, buf.AsMemory(0, op.BytesWritten), cancellationToken);
			}
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buf);
		}
	}

	// ── Dispose ─────────────────────────────────────────────

	public ValueTask DisposeAsync()
	{
		if (_disposed)
		{
			return ValueTask.CompletedTask;
		}

		_disposed = true;
		Session.Dispose();
		return ValueTask.CompletedTask;
	}

	// ── Private helpers ─────────────────────────────────────

	private async ValueTask<int> ReceiveOrThrow(byte[] buf, CancellationToken cancellationToken = default)
	{
		int n = await _transport.ReceiveAsync(buf, cancellationToken);

		if (n > 0)
		{
			return n;
		}

		throw new DtlsException
		(
			Interop.DtlsResult.DtlsError,
			"Transport closed during handshake"
		);
	}

	private static async ValueTask SendFramedAsync(IDatagramTransport transport, ReadOnlyMemory<byte> framed, CancellationToken cancellationToken = default)
	{
		while (BinaryPrimitives.TryReadUInt16LittleEndian(framed.Span, out ushort len))
		{
			framed = framed.Slice(sizeof(ushort));

			if (len > framed.Length)
			{
				break;
			}

			await transport.SendAsync(framed.Slice(0, len), cancellationToken);
			framed = framed.Slice(len);
		}
	}
}
