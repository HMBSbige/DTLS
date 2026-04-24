using DTLS.Common;
using DTLS.Dtls;
using System.Security.Authentication;

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

	[Test]
	public async Task CloseAsync_PeerSeesIsPeerClosed(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);

		await DrivePeerCloseAsync(s, cancellationToken);

		await Assert.That(s.Session.IsPeerClosed).IsTrue();
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
	public async Task CloseAsync_LocalSideMarksIsClosed(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
		await Assert.That(c.Session.IsPeerClosed).IsFalse();
	}

	/// <summary>
	/// RFC 9147 §5.10 回归：DTLS 1.3 下 close_notify 乱序早于 pre-close app data 到达时，
	/// server 仍必须投递后到达的合法 app data，不得因已收到 close_notify 而截断。
	/// </summary>
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
				Version = SslProtocols.Tls13,
				RemoteCertificateValidation = (_, _, _) => true
			}
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert, Version = SslProtocols.Tls13 }
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
			new DtlsClientOptions { ServerName = "localhost", RemoteCertificateValidation = (_, _, _) => true }
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		await Task.WhenAll
		(
			c.HandshakeAsync(cancellationToken).AsTask(),
			s.HandshakeAsync(cancellationToken).AsTask()
		);

		clientTransport.Arm();
		await Assert.That(async () => await c.CloseAsync(cancellationToken)).Throws<InvalidOperationException>();

		// 瞬时失败后重试必须真实投递 close_notify
		await c.CloseAsync(cancellationToken);

		await DrivePeerCloseAsync(s, cancellationToken);

		await Assert.That(s.Session.IsPeerClosed).IsTrue();
	}

	[Test]
	public async Task CloseAsync_BeforeHandshakeIsNoopAndRetriable(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions { ServerName = "localhost", RemoteCertificateValidation = (_, _, _) => true }
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		// 握手尚未完成时调用 CloseAsync：dimpl HandshakePending，不得把会话闩死
		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsFalse();

		await Task.WhenAll
		(
			c.HandshakeAsync(cancellationToken).AsTask(),
			s.HandshakeAsync(cancellationToken).AsTask()
		);

		// 握手完成后再次 CloseAsync 必须真实生效
		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task CloseAsync_DuringPendingHandshake_DoesNotLeakHandshakeFlight(CancellationToken cancellationToken)
	{
		(IDatagramTransport rawClient, IDatagramTransport _) = CreateTransportPair();
		CountingTransport clientTransport = new(rawClient);

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions { ServerName = "localhost", RemoteCertificateValidation = (_, _, _) => true }
		);

		// CreateClientAsync 会发出初始 ClientHello
		int sendsAfterCreate = clientTransport.SendCount;
		await Assert.That(sendsAfterCreate).IsEqualTo(1);

		// 等重传定时器到期：握手期 CloseAsync 不得产出任何数据（不得把重传握手 flight 当 close_notify 发出），
		// 也不得把会话标记为已关闭或短路后续重试。
		if (c.Session.TimeoutMs > 0)
		{
			await Task.Delay((int)c.Session.TimeoutMs + 50, cancellationToken);
		}

		await c.CloseAsync(cancellationToken);

		await Assert.That(clientTransport.SendCount).IsEqualTo(sendsAfterCreate);
		await Assert.That(c.Session.IsLocalClosed).IsFalse();
		await Assert.That(c.Session.IsHandshaking).IsTrue();

		// 再次 CloseAsync 仍必须是合法 no-op（不短路也不抛），握手完成前都应保持可重试
		await c.CloseAsync(cancellationToken);
		await Assert.That(clientTransport.SendCount).IsEqualTo(sendsAfterCreate);
		await Assert.That(c.Session.IsLocalClosed).IsFalse();
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
				Version = SslProtocols.Tls13,
				RemoteCertificateValidation = (_, _, _) => true
			}
		);

		await c.CloseAsync(cancellationToken);

		// 固定版本下 dimpl 在握手前可闩死会话；状态快照必须反映"已关闭、不再握手"，
		// 否则后续 HandshakeAsync 会用过大的 TimeoutMs 触发 ArgumentOutOfRangeException。
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
		await Assert.That(c.Session.IsHandshaking).IsFalse();
		await Assert.That(c.Session.TimeoutMs).IsEqualTo(-1);

		// 原始失败序列：CloseAsync(); HandshakeAsync();
		// 不得再抛 ArgumentOutOfRangeException；应以 DtlsException 明确报告会话已关闭。
		await Assert.That(async () => await c.HandshakeAsync(cancellationToken)).Throws<DtlsException>();
	}

	[Test]
	public async Task CloseAsync_BeforeHandshakeWithFixedVersionLatchesSession()
	{
		(IDatagramTransport clientTransport, IDatagramTransport _) = CreateTransportPair();

		byte[] buf = new byte[65536];
		(DtlsSession session, _) = DtlsSession.CreateClient
		(
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls13,
				RemoteCertificateValidation = (_, _, _) => true
			},
			buf
		);

		using (session)
		{
			// 固定版本握手中途调用 Close()：dimpl 直接中止会话，不产出 datagram；
			// Session.IsLocalClosed 必须反映真实的底层关闭状态，而不是依赖 BytesWritten 推断。
			DtlsOpResult op = session.Close(buf);
			await Assert.That(op.BytesWritten).IsEqualTo(0);
			await Assert.That(session.IsLocalClosed).IsTrue();
		}
	}

	[Test]
	public async Task Close_TooSmallOutputBuffer_SyncsStateBeforeThrowing(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		// 用一个只有 1 字节的缓冲区调用底层 Close，强制触发 BufferTooSmall；
		// 即便抛异常，Session.IsLocalClosed 仍必须同步为 true，反映 dimpl 的真实状态。
		byte[] tiny = new byte[1];
		await Assert.That(() => c.Session.Close(tiny)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task Send_AfterLocalClose_ErrorDoesNotWipeCloseState(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();

		// 本端已 close 后再发送会走 Rust 错误路径：异常必须抛，但 IsLocalClosed 不得被清零
		await Assert.That(async () => await c.SendAsync(new byte[] { 1, 2, 3 }, cancellationToken)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task Send_OversizedPayloadAfterClose_ErrorDoesNotWipeCloseState(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();

		// 超过 native 1 MiB 上限，触发 Rust 的 InvalidInput 早返回路径；状态字段必须保真
		byte[] oversized = new byte[1024 * 1024 + 1];
		byte[] outBuf = new byte[65536];
		await Assert.That(() => c.Session.Send(oversized, outBuf)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task Feed_OversizedPayloadAfterClose_ErrorDoesNotWipeCloseState(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await c.CloseAsync(cancellationToken);
		await Assert.That(c.Session.IsLocalClosed).IsTrue();

		// 同样验证 Feed 的 > 1 MiB 早返回路径：抛异常后 IsLocalClosed 必须保持 true
		byte[] oversized = new byte[1024 * 1024 + 1];
		byte[] outBuf = new byte[65536];
		await Assert.That(() => c.Session.Feed(oversized, outBuf)).Throws<DtlsException>();
		await Assert.That(c.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task PeerCloseNotify_InDtls13_AllowsLocalReciprocalClose(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls13,
				RemoteCertificateValidation = (_, _, _) => true
			}
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert, Version = SslProtocols.Tls13 }
		);

		await Task.WhenAll
		(
			c.HandshakeAsync(cancellationToken).AsTask(),
			s.HandshakeAsync(cancellationToken).AsTask()
		);

		await c.CloseAsync(cancellationToken);

		// 驱动 server 处理 close_notify
		await DrivePeerCloseAsync(s, cancellationToken);

		// DTLS 1.3 半关：server 收到对端 close_notify 后仍可主动发自己的 close_notify
		await Assert.That(s.Session.IsLocalClosed).IsFalse();
		await s.CloseAsync(cancellationToken);
		await Assert.That(s.Session.IsLocalClosed).IsTrue();
	}

	[Test]
	public async Task PeerCloseNotify_InDtls12_MarksIsLocalClosed(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport c = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls12,
				RemoteCertificateValidation = (_, _, _) => true
			}
		);
		await using DtlsTransport s = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert, Version = SslProtocols.Tls12 }
		);

		await Task.WhenAll
		(
			c.HandshakeAsync(cancellationToken).AsTask(),
			s.HandshakeAsync(cancellationToken).AsTask()
		);

		await c.CloseAsync(cancellationToken);

		// 驱动 server 处理 close_notify。DTLS 1.2 下 dimpl 会自动关闭本地写方向，
		// 因此 server.Session.IsLocalClosed 必须随之变为 true。
		await DrivePeerCloseAsync(s, cancellationToken);

		await Assert.That(s.Session.IsPeerClosed).IsTrue();
		await Assert.That(s.Session.IsLocalClosed).IsTrue();
	}
}
