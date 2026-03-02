using DTLS.Common;
using DTLS.Dtls;

namespace DTLS.Tests;

public class DtlsDataTransferTests : DtlsTestBase
{
	[Test]
	public async Task DataTransfer_RoundTrip(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[32];
		Random.Shared.NextBytes(payload.Span);
		await c.SendAsync(payload, cancellationToken);

		Memory<byte> buffer = new byte[1024];
		int n = await s.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
	}

	[Test]
	public async Task DataTransfer_ServerToClient(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[48];
		Random.Shared.NextBytes(payload.Span);
		await s.SendAsync(payload, cancellationToken);

		Memory<byte> buffer = new byte[1024];
		int n = await c.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
	}

	[Test]
	public async Task DataTransfer_MultipleMessages(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[16];
		Memory<byte> buffer = new byte[1024];

		for (int i = 0; i < 3; i++)
		{
			Random.Shared.NextBytes(payload.Span);
			await c.SendAsync(payload, cancellationToken);

			int n = await s.ReceiveAsync(buffer, cancellationToken);
			await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
		}
	}

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
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			closableServer,
			new DtlsServerOptions { Certificate = Cert }
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
	public async Task ReceiveAsync_ThrowsWhenBufferTooSmall(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		Memory<byte> payload = new byte[64];
		Random.Shared.NextBytes(payload.Span);
		await client.SendAsync(payload, cancellationToken);

		Memory<byte> tiny = new byte[8];
		await Assert.That(async () => await server.ReceiveAsync(tiny, cancellationToken)).Throws<DtlsException>();
	}

	[Test]
	public async Task SendAsync_ThrowsObjectDisposedException_AfterDispose(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await server.DisposeAsync();

		await using DtlsTransport _ = client;
		await Assert.That(async () => await server.SendAsync(new byte[16], cancellationToken)).Throws<ObjectDisposedException>();
	}

	[Test]
	public async Task ReceiveAsync_ThrowsObjectDisposedException_AfterDispose(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await client.DisposeAsync();

		await using DtlsTransport _ = server;
		await Assert.That(async () => await client.ReceiveAsync(new byte[1024], cancellationToken)).Throws<ObjectDisposedException>();
	}

	[Test]
	public async Task ReceiveAsync_ThrowsOperationCanceledException_WhenCancelled(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		using CancellationTokenSource cts = new();
		cts.CancelAfter(TimeSpan.FromMilliseconds(50));
		await Assert.That(async () => await server.ReceiveAsync(new byte[1024], cts.Token)).Throws<OperationCanceledException>();
	}

	[Test]
	public async Task SendAsync_EmptyPayload_DoesNotThrow(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		await client.SendAsync(ReadOnlyMemory<byte>.Empty, cancellationToken);
	}

	[Test]
	[Arguments(8192)]
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
	public async Task DataTransfer_BidirectionalConcurrent(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		Memory<byte> clientPayload = new byte[32];
		Memory<byte> serverPayload = new byte[32];
		Random.Shared.NextBytes(clientPayload.Span);
		Random.Shared.NextBytes(serverPayload.Span);

		await Task.WhenAll
		(
			client.SendAsync(clientPayload, cancellationToken).AsTask(),
			server.SendAsync(serverPayload, cancellationToken).AsTask()
		);

		Memory<byte> buffer = new byte[1024];
		int n1 = await server.ReceiveAsync(buffer, cancellationToken);

		await Assert.That(buffer.Slice(0, n1).Span.SequenceEqual(clientPayload.Span)).IsTrue();

		int n2 = await client.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n2).Span.SequenceEqual(serverPayload.Span)).IsTrue();
	}

	[Test]
	public async Task DisposeAsync_Idempotent(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = client;

		await server.DisposeAsync();
		await server.DisposeAsync();// second call should not throw
	}
}
