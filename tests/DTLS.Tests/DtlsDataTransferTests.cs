using DTLS.Common;
using DTLS.Dtls;
using DTLS.Interop;

// ReSharper disable AccessToDisposedClosure

namespace DTLS.Tests;

public class DtlsDataTransferTests : DtlsTestBase
{
	[Test]
	public async Task ReceiveAsync_ReturnsZero_WhenTransportClosed(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();
		ClosableTransport closableServer = new(serverTransport);

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			closableServer,
			new DtlsServerOptions { Certificate = Cert },
			cancellationToken
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		closableServer.Close();
		Memory<byte> buffer = new byte[1024];
		int n = await server.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(n).IsEqualTo(0);
	}

	[Test]
	public async Task ReceiveAsync_BufferTooSmall_PreservesDatagramForRetry(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport clientLifetime = client;
		await using DtlsTransport serverLifetime = server;

		Memory<byte> payload = new byte[64];
		Random.Shared.NextBytes(payload.Span);
		await client.SendAsync(payload, cancellationToken);

		Memory<byte> tiny = new byte[8];
		DtlsException? exception = await Assert.That(async () => await server.ReceiveAsync(tiny, cancellationToken)).Throws<DtlsException>();
		await Assert.That(exception?.ErrorCode).IsEqualTo(DtlsResult.BufferTooSmall);

		Memory<byte> buffer = new byte[payload.Length];
		int received = await server.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, received).Span.SequenceEqual(payload.Span)).IsTrue();
		await Assert.That(server.Session.TryReceive(buffer.Span, out _)).IsFalse();
	}

	[Test]
	public async Task ReceiveAsync_ThrowsOperationCanceledException_WhenCancelled(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		cts.CancelAfter(TimeSpan.FromMilliseconds(50));
		await Assert.That(async () => await server.ReceiveAsync(new byte[1024], cts.Token)).Throws<OperationCanceledException>();
	}

	[Test]
	public async Task SendAsync_BeforeHandshakeIsFatal(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport _) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);

		await Assert.That
		(async () => await client.SendAsync(new byte[] { 1 }, cancellationToken)
		).Throws<DtlsException>();

		await Assert.That(client.Session.IsHandshaking).IsFalse();
	}

	[Test]
	[Arguments(16384)]
	[Arguments(16385)]
	public async Task DataTransfer_LargePayload(int size, CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		Memory<byte> payload = new byte[size];
		Random.Shared.NextBytes(payload.Span);
		await client.SendAsync(payload, cancellationToken);

		Memory<byte> buffer = new byte[size];
		int n = await server.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
	}

	[Test]
	public async Task DataTransfer_BidirectionalConcurrent_PreservesDatagramBoundaries(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		byte[][] clientPayloads = [[1], [2, 3, 4], [5, 6]];
		byte[][] serverPayloads = [[7, 8], [9], [10, 11, 12]];

		await Task.WhenAll
		(
			ReceiveAllAsync(client, serverPayloads),
			ReceiveAllAsync(server, clientPayloads),
			SendAllAsync(client, clientPayloads),
			SendAllAsync(server, serverPayloads)
		);

		async Task SendAllAsync(DtlsTransport sender, byte[][] payloads)
		{
			foreach (byte[] payload in payloads)
			{
				await sender.SendAsync(payload, cancellationToken);
			}
		}

		async Task ReceiveAllAsync(DtlsTransport receiver, byte[][] payloads)
		{
			Memory<byte> buffer = new byte[1024];

			foreach (byte[] payload in payloads)
			{
				int received = await receiver.ReceiveAsync(buffer, cancellationToken);
				await Assert.That(buffer.Slice(0, received).Span.SequenceEqual(payload)).IsTrue();
			}
		}
	}

	[Test]
	public async Task DisposeAsync_RejectsFurtherIoAndCanBeRepeated(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;

		await server.DisposeAsync();
		await server.DisposeAsync();
		await Assert.That(async () => await server.SendAsync(new byte[] { 1 }, cancellationToken)).Throws<ObjectDisposedException>();
		await Assert.That(async () => await server.ReceiveAsync(new byte[1024], cancellationToken)).Throws<ObjectDisposedException>();
	}

	[Test]
	public async Task CloseAsync_AppDataBeforeCloseIsDelivered(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[64];
		Random.Shared.NextBytes(payload.Span);
		await c.SendAsync(payload, cancellationToken);
		await c.CloseAsync(cancellationToken);

		Memory<byte> buffer = new byte[1024];
		int n = await s.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
	}

	[Test]
	public async Task CloseAsync_OutOfOrderAppDataAfterCloseNotifyIsDelivered(CancellationToken cancellationToken)
	{
		(IDatagramTransport rawClient, IDatagramTransport serverTransport) = CreateTransportPair();
		ArmedSwapTransport clientTransport = new(rawClient);

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				MinVersion = DtlsVersion.Dtls13,
				MaxVersion = DtlsVersion.Dtls13,
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				MinVersion = DtlsVersion.Dtls13,
				MaxVersion = DtlsVersion.Dtls13
			},
			cancellationToken
		);

		await Task.WhenAll
		(
			c.HandshakeAsync(cancellationToken).AsTask(),
			s.HandshakeAsync(cancellationToken).AsTask()
		);

		clientTransport.Arm();

		Memory<byte> payload = new byte[32];
		Random.Shared.NextBytes(payload.Span);
		await c.SendAsync(payload, cancellationToken);
		await c.CloseAsync(cancellationToken);

		Memory<byte> buffer = new byte[1024];
		int n = await s.ReceiveAsync(buffer, cancellationToken);

		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
	}

	[Test]
	public async Task CloseAsync_IsRetriableAfterTransientSendFailure(CancellationToken cancellationToken)
	{
		(IDatagramTransport rawClient, IDatagramTransport serverTransport) = CreateTransportPair();
		FailNextSendTransport clientTransport = new(rawClient, new InvalidOperationException("send failed"));

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert },
			cancellationToken
		);

		await Task.WhenAll
		(
			c.HandshakeAsync(cancellationToken).AsTask(),
			s.HandshakeAsync(cancellationToken).AsTask()
		);

		clientTransport.Arm();
		await Assert.That(async () => await c.CloseAsync(cancellationToken)).Throws<InvalidOperationException>();

		await c.CloseAsync(cancellationToken);

		await DrivePeerCloseAsync(s, cancellationToken);

		await Assert.That(s.Session.IsPeerClosed).IsTrue();
	}

	[Test]
	public async Task CloseAsync_DuringPendingHandshake_DoesNotLeakHandshakeFlight(CancellationToken cancellationToken)
	{
		(IDatagramTransport rawClient, IDatagramTransport _) = CreateTransportPair();
		CountingTransport clientTransport = new(rawClient);

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);

		int sendsBeforeClose = clientTransport.SendCount;
		await Assert.That(sendsBeforeClose).IsGreaterThan(0);

		// Make a handshake retransmission due before closing.
		if (c.Session.Timeout is { } timeout && timeout > TimeSpan.Zero)
		{
			await Task.Delay(timeout + TimeSpan.FromMilliseconds(50), cancellationToken);
		}

		await Assert.That(async () => await c.CloseAsync(cancellationToken)).Throws<DtlsException>();

		await Assert.That(clientTransport.SendCount).IsEqualTo(sendsBeforeClose);
		await Assert.That(c.Session.IsHandshaking).IsFalse();
		await Assert.That(c.Session.Timeout).IsNull();
	}

	[Test]
	public async Task CloseAsync_BeforeHandshakeWithFixedVersion_ClearsStateAndBlocksFurtherHandshake(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport _) = CreateTransportPair();

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				MinVersion = DtlsVersion.Dtls13,
				MaxVersion = DtlsVersion.Dtls13,
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);

		await c.CloseAsync(cancellationToken);

		await Assert.That(c.Session.IsLocalClosed).IsTrue();
		await Assert.That(c.Session.IsHandshaking).IsFalse();
		await Assert.That(c.Session.Timeout).IsNull();

		await Assert.That(async () => await c.HandshakeAsync(cancellationToken)).Throws<DtlsException>();
	}

	[Test]
	public async Task Close_TooSmallOutputBuffer_PreservesCloseNotifyForRetry(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		byte[] tiny = new byte[1];
		DtlsException? exception = await Assert.That(() => c.Session.Close(tiny)).Throws<DtlsException>();
		await Assert.That(exception?.ErrorCode).IsEqualTo(DtlsResult.BufferTooSmall);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();

		await c.CloseAsync(cancellationToken);
		await DrivePeerCloseAsync(s, cancellationToken);
		await Assert.That(s.Session.IsPeerClosed).IsTrue();
	}

	[Test]
	public async Task Send_AfterLocalClose_ErrorDoesNotWipeCloseState(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();

		await Assert.That(async () => await c.SendAsync(new byte[] { 1, 2, 3 }, cancellationToken)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task OversizedInputAfterClose_DoesNotWipeCloseState(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();

		// The FFI rejects inputs larger than 1 MiB.
		byte[] oversized = new byte[1024 * 1024 + 1];
		byte[] outBuf = new byte[65536];
		await Assert.That(() => c.Session.Send(oversized, outBuf)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
		await Assert.That(() => c.Session.Feed(oversized, outBuf)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task PeerCloseNotify_InDtls13_AllowsLocalReciprocalClose(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken, DtlsVersion.Dtls13);
		await using DtlsTransport clientLifetime = c;
		await using DtlsTransport serverLifetime = s;

		await c.CloseAsync(cancellationToken);

		await DrivePeerCloseAsync(s, cancellationToken);

		await Assert.That(s.Session.IsLocalClosed).IsFalse();
		await s.CloseAsync(cancellationToken);
		await Assert.That(s.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task PeerCloseNotify_InDtls12_MarksIsLocalClosed(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken, DtlsVersion.Dtls12);
		await using DtlsTransport clientLifetime = c;
		await using DtlsTransport serverLifetime = s;

		await c.CloseAsync(cancellationToken);

		await DrivePeerCloseAsync(s, cancellationToken);

		await Assert.That(s.Session.IsPeerClosed).IsTrue();
		await Assert.That(s.Session.IsLocalClosed).IsTrue();
	}
}
