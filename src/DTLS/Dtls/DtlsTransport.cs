using DTLS.Common;
using DTLS.Interop;
using System.Buffers;
using System.Buffers.Binary;

namespace DTLS.Dtls;

/// <remarks>
/// Complete <see cref="HandshakeAsync"/> before exchanging application data.
/// The caller owns the underlying transport.
/// </remarks>
public sealed class DtlsTransport : IDatagramTransport, IAsyncDisposable, IDisposable
{
	private const int IoBufferSize = 65536;
	private static readonly TimeSpan MaximumTimeout = TimeSpan.FromMilliseconds(uint.MaxValue - 1);
	private readonly TimeSpan _handshakeTimeout;
	private bool _disposed;
	private byte[]? _closeNotify;
	private bool _closeNotifySent;

	public IDatagramTransport InnerTransport { get; }

	public DtlsSession Session { get; }

	private DtlsTransport(DtlsSession session, IDatagramTransport transport, TimeSpan handshakeTimeout)
	{
		Session = session;
		InnerTransport = transport;
		_handshakeTimeout = handshakeTimeout;
	}

	public static ValueTask<DtlsTransport> CreateClientAsync(IDatagramTransport transport, DtlsClientOptions options, CancellationToken cancellationToken = default)
	{
		return CreateAsync(transport, options, DtlsSession.CreateClient, cancellationToken);
	}

	public static ValueTask<DtlsTransport> CreateServerAsync(IDatagramTransport transport, DtlsServerOptions options, CancellationToken cancellationToken = default)
	{
		return CreateAsync(transport, options, DtlsSession.CreateServer, cancellationToken);
	}

	public async ValueTask HandshakeAsync(CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		Session.ThrowIfUnavailable();
		cancellationToken.ThrowIfCancellationRequested();

		if (Session.IsLocalClosed)
		{
			throw new DtlsException(DtlsResult.DtlsError, "Cannot handshake a closed DTLS session.");
		}

		if (!Session.IsHandshaking)
		{
			return;
		}

		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(_handshakeTimeout);
		byte[] buffer = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			while (Session.IsHandshaking)
			{
				if (!await ReceiveAndFeedAsync(buffer, timeout.Token))
				{
					throw new DtlsException(DtlsResult.DtlsError, "Transport closed during the DTLS handshake.");
				}
			}
		}
		catch (OperationCanceledException exception) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
		{
			throw new DtlsTimeoutException("DTLS handshake timed out.", exception);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		cancellationToken.ThrowIfCancellationRequested();
		byte[] buffer = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			DtlsOpResult result = Session.Send(datagram.Span, buffer);
			await SendFramedAsync(InnerTransport, buffer.AsMemory(0, result.BytesWritten), cancellationToken);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		cancellationToken.ThrowIfCancellationRequested();
		if (Session.TryReceive(buffer.Span, out int bytesRead))
		{
			return bytesRead;
		}

		byte[] ioBuffer = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			do
			{
				if (!await ReceiveAndFeedAsync(ioBuffer, cancellationToken))
				{
					return 0;
				}
			} while (!Session.TryReceive(buffer.Span, out bytesRead));

			return bytesRead;
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(ioBuffer);
		}
	}

	/// <summary>Sends <c>close_notify</c> without waiting for the peer. Failed sends can be retried.</summary>
	public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		cancellationToken.ThrowIfCancellationRequested();

		if (_closeNotifySent)
		{
			return;
		}

		_closeNotify ??= CreateCloseNotify();
		await SendFramedAsync(InnerTransport, _closeNotify, cancellationToken);
		_closeNotifySent = true;
		_closeNotify = null;
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_closeNotify = null;
		Session.Dispose();
	}

	public ValueTask DisposeAsync()
	{
		Dispose();
		return ValueTask.CompletedTask;
	}

	private delegate (DtlsSession Session, DtlsOpResult Result) SessionFactory<in TOptions>(TOptions options, Span<byte> output);

	private static async ValueTask<DtlsTransport> CreateAsync<TOptions>(IDatagramTransport transport, TOptions options, SessionFactory<TOptions> createSession, CancellationToken cancellationToken) where TOptions : DtlsOptions
	{
		ArgumentNullException.ThrowIfNull(transport);
		ArgumentNullException.ThrowIfNull(options);

		if (options.HandshakeTimeout != Timeout.InfiniteTimeSpan)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(options.HandshakeTimeout, TimeSpan.Zero, nameof(options.HandshakeTimeout));
			ArgumentOutOfRangeException.ThrowIfGreaterThan(options.HandshakeTimeout, MaximumTimeout, nameof(options.HandshakeTimeout));
		}

		cancellationToken.ThrowIfCancellationRequested();
		byte[] buffer = ArrayPool<byte>.Shared.Rent(IoBufferSize);
		DtlsSession? session = null;

		try
		{
			(session, DtlsOpResult result) = createSession(options, buffer);
			await SendFramedAsync(transport, buffer.AsMemory(0, result.BytesWritten), cancellationToken);
			return new DtlsTransport(session, transport, options.HandshakeTimeout);
		}
		catch
		{
			session?.Dispose();
			throw;
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	private async ValueTask<bool> ReceiveAndFeedAsync(byte[] buffer, CancellationToken cancellationToken)
	{
		using CancellationTokenSource? timeout = CreateReceiveTimeout(cancellationToken);
		int? bytesRead = null;

		try
		{
			bytesRead = await InnerTransport.ReceiveAsync(buffer, timeout?.Token ?? cancellationToken);
		}
		catch (OperationCanceledException) when (timeout is { IsCancellationRequested: true } && !cancellationToken.IsCancellationRequested)
		{
		}

		if (bytesRead is 0)
		{
			return false;
		}

		DtlsOpResult result = bytesRead is { } count
			? Session.Feed(buffer.AsSpan(0, count), buffer)
			: Session.HandleTimeout(buffer);
		await SendFramedAsync(InnerTransport, buffer.AsMemory(0, result.BytesWritten), cancellationToken);
		return true;
	}

	private CancellationTokenSource? CreateReceiveTimeout(CancellationToken cancellationToken)
	{
		if (Session.Timeout is not { } delay)
		{
			return null;
		}

		CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(TimeSpan.FromMilliseconds(Math.Clamp(delay.TotalMilliseconds, 1, MaximumTimeout.TotalMilliseconds)));
		return timeout;
	}

	private byte[] CreateCloseNotify()
	{
		byte[] buffer = ArrayPool<byte>.Shared.Rent(IoBufferSize);

		try
		{
			DtlsOpResult result = Session.Close(buffer);
			return buffer.AsSpan(0, result.BytesWritten).ToArray();
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	private static async ValueTask SendFramedAsync(IDatagramTransport transport, ReadOnlyMemory<byte> framed, CancellationToken cancellationToken)
	{
		while (!framed.IsEmpty)
		{
			if (!BinaryPrimitives.TryReadUInt16LittleEndian(framed.Span, out ushort length) || length > framed.Length - sizeof(ushort))
			{
				throw new InvalidDataException("The DTLS session returned an incomplete datagram frame.");
			}

			cancellationToken.ThrowIfCancellationRequested();
			await transport.SendAsync(framed.Slice(sizeof(ushort), length), cancellationToken);
			framed = framed.Slice(sizeof(ushort) + length);
		}
	}
}
