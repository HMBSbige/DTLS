using DTLS.Common;
using DTLS.Dtls;

// ReSharper disable AccessToDisposedClosure

namespace DTLS.Tests;

public class DtlsTransportContractTests : DtlsTestBase
{
	[Test]
	public async Task CreateClient_WhenAlreadyCancelled_DoesNotSend()
	{
		CountingTransport transport = new(new BlackHoleTransport());
		using CancellationTokenSource cancelled = new();
		cancelled.Cancel();

		await Assert.That(async () => await DtlsTransport.CreateClientAsync(transport, new DtlsClientOptions { ServerName = "localhost" }, cancelled.Token)).Throws<OperationCanceledException>();
		await Assert.That(transport.SendCount).IsEqualTo(0);
	}

	[Test]
	public async Task CreateClient_CancelsPendingInitialSend(CancellationToken cancellationToken)
	{
		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(TimeSpan.FromMilliseconds(100));

		await Assert.That(async () => await DtlsTransport.CreateClientAsync(new BlockingSendTransport(), new DtlsClientOptions { ServerName = "localhost" }, timeout.Token).AsTask().WaitAsync(TimeSpan.FromSeconds(5), cancellationToken)).Throws<OperationCanceledException>();
	}

	[Test]
	[Arguments(-2L)]
	[Arguments(4294967295L)]
	public async Task CreateClient_RejectsInvalidTimeoutBeforeSending(long milliseconds, CancellationToken cancellationToken)
	{
		CountingTransport transport = new(new BlackHoleTransport());

		await Assert.That
		(async () => await DtlsTransport.CreateClientAsync
			(
				transport, new DtlsClientOptions
				{
					ServerName = "localhost",
					HandshakeTimeout = TimeSpan.FromMilliseconds(milliseconds)
				}, cancellationToken
			)
		).Throws<ArgumentOutOfRangeException>();
		await Assert.That(transport.SendCount).IsEqualTo(0);
	}

	[Test]
	public async Task Handshake_PreservesTransportCancellation(CancellationToken cancellationToken)
	{
		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			new IndependentlyCancelledTransport(), new DtlsClientOptions
			{
				ServerName = "localhost",
				HandshakeTimeout = TimeSpan.FromMilliseconds(100)
			}, cancellationToken
		);

		await Assert.That(async () => await client.HandshakeAsync(cancellationToken)).Throws<OperationCanceledException>();
	}

	[Test]
	public async Task Handshake_AfterSessionDisposed_Throws(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport clientLifetime = client;
		await using DtlsTransport serverLifetime = server;
		client.Session.Dispose();

		await Assert.That(async () => await client.HandshakeAsync(cancellationToken)).Throws<ObjectDisposedException>();
	}

	[Test]
	public async Task Close_WhenAlreadyCancelled_DoesNotCloseSession(CancellationToken cancellationToken)
	{
		(DtlsTransport client, DtlsTransport server) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport clientLifetime = client;
		await using DtlsTransport serverLifetime = server;
		using CancellationTokenSource cancelled = new();
		cancelled.Cancel();

		await Assert.That(async () => await client.CloseAsync(cancelled.Token)).Throws<OperationCanceledException>();
		await Assert.That(client.Session.IsLocalClosed).IsFalse();

		await client.SendAsync(new byte[] { 42 }, cancellationToken);
		byte[] buffer = new byte[1];
		await Assert.That(await server.ReceiveAsync(buffer, cancellationToken)).IsEqualTo(1);
		await Assert.That(buffer[0]).IsEqualTo((byte)42);
	}

	private sealed class BlockingSendTransport : IDatagramTransport
	{
		public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			return ValueTask.FromResult(0);
		}

		public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
		{
			await Task.Delay(Timeout.Infinite, cancellationToken);
		}
	}

	private sealed class IndependentlyCancelledTransport : IDatagramTransport
	{
		private bool _cancelled;

		public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			if (!_cancelled)
			{
				_cancelled = true;
				throw new OperationCanceledException("The underlying transport was cancelled independently.");
			}

			await Task.Delay(Timeout.Infinite, cancellationToken);
			return 0;
		}

		public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
		{
			return ValueTask.CompletedTask;
		}
	}
}
