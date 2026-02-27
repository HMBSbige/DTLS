using DTLS.Common;
using DTLS.Dtls;

namespace DTLS.Tests;

public class DtlsDataTransferTests : DtlsTestBase
{
	[Fact]
	public async Task DataTransfer_RoundTrip()
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[32];
		Random.Shared.NextBytes(payload.Span);
		await c.SendAsync(payload, TestContext.Current.CancellationToken);

		Memory<byte> buffer = new byte[1024];
		int n = await s.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
		Assert.Equal(payload, buffer.Slice(0, n));
	}

	[Fact]
	public async Task DataTransfer_ServerToClient()
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[48];
		Random.Shared.NextBytes(payload.Span);
		await s.SendAsync(payload, TestContext.Current.CancellationToken);

		Memory<byte> buffer = new byte[1024];
		int n = await c.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
		Assert.Equal(payload, buffer.Slice(0, n));
	}

	[Fact]
	public async Task DataTransfer_MultipleMessages()
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Memory<byte> payload = new byte[16];
		Memory<byte> buffer = new byte[1024];

		for (int i = 0; i < 3; i++)
		{
			Random.Shared.NextBytes(payload.Span);
			await c.SendAsync(payload, TestContext.Current.CancellationToken);

			int n = await s.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
			Assert.Equal(payload, buffer.Slice(0, n));
		}
	}

	[Fact]
	public async Task ReceiveAsync_ReturnsZero_WhenTransportClosed()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		closableServer.Close();
		Memory<byte> buffer = new byte[1024];
		int n = await server.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
		Assert.Equal(0, n);
	}

	[Fact]
	public async Task ReceiveAsync_ThrowsWhenBufferTooSmall()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		Memory<byte> payload = new byte[64];
		Random.Shared.NextBytes(payload.Span);
		await client.SendAsync(payload, TestContext.Current.CancellationToken);

		Memory<byte> tiny = new byte[8];
		await Assert.ThrowsAsync<DtlsException>(() => server.ReceiveAsync(tiny, TestContext.Current.CancellationToken).AsTask());
	}

	[Fact]
	public async Task SendAsync_ThrowsObjectDisposedException_AfterDispose()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await server.DisposeAsync();

		await using DtlsTransport _ = client;
		await Assert.ThrowsAsync<ObjectDisposedException>(() => server.SendAsync(new byte[16], TestContext.Current.CancellationToken).AsTask());
	}

	[Fact]
	public async Task ReceiveAsync_ThrowsObjectDisposedException_AfterDispose()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await client.DisposeAsync();

		await using DtlsTransport _ = server;
		await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ReceiveAsync(new byte[1024], TestContext.Current.CancellationToken).AsTask());
	}

	[Fact]
	public async Task ReceiveAsync_ThrowsOperationCanceledException_WhenCancelled()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		using CancellationTokenSource cts = new();
		cts.CancelAfter(TimeSpan.FromMilliseconds(50));
		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => server.ReceiveAsync(new byte[1024], cts.Token).AsTask());
	}

	[Fact]
	public async Task SendAsync_EmptyPayload_DoesNotThrow()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		await client.SendAsync(ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken);
	}

	[Theory]
	[InlineData(8192)]
	[InlineData(16384)]
	[InlineData(16385)]
	public async Task DataTransfer_LargePayload(int size)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		Memory<byte> payload = new byte[size];
		Random.Shared.NextBytes(payload.Span);
		await client.SendAsync(payload, TestContext.Current.CancellationToken);

		Memory<byte> buffer = new byte[size];
		int n = await server.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
		Assert.Equal(payload, buffer.Slice(0, n));
	}

	[Fact]
	public async Task DataTransfer_BidirectionalConcurrent()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = client;
		await using DtlsTransport __ = server;

		Memory<byte> clientPayload = new byte[32];
		Memory<byte> serverPayload = new byte[32];
		Random.Shared.NextBytes(clientPayload.Span);
		Random.Shared.NextBytes(serverPayload.Span);

		await Task.WhenAll
		(
			client.SendAsync(clientPayload, TestContext.Current.CancellationToken).AsTask(),
			server.SendAsync(serverPayload, TestContext.Current.CancellationToken).AsTask()
		);

		Memory<byte> buffer = new byte[1024];
		int n1 = await server.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
		Assert.Equal(clientPayload, buffer.Slice(0, n1));

		int n2 = await client.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
		Assert.Equal(serverPayload, buffer.Slice(0, n2));
	}

	[Fact]
	public async Task DisposeAsync_Idempotent()
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = client;

		await server.DisposeAsync();
		await server.DisposeAsync();// second call should not throw
	}
}
