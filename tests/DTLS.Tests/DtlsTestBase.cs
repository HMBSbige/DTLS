using DTLS.Common;
using DTLS.Dtls;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

public abstract class DtlsTestBase : IDisposable
{
	protected readonly X509Certificate2 Cert = TestCertificateFactory.CreateEcdsaSelfSigned();

	public void Dispose()
	{
		Cert.Dispose();
		GC.SuppressFinalize(this);
	}

	protected async Task<(DtlsTransport Client, DtlsTransport Server)> HandshakePairAsync(CancellationToken cancellationToken = default)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();
		DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) => true
			}
		);
		DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);
		return (client, server);
	}

	protected static (IDatagramTransport client, IDatagramTransport server) CreateTransportPair()
	{
		return ChannelDatagramTransport.CreatePair();
	}

	/// <summary>
	/// 驱动 <paramref name="peer"/> 的 ReceiveAsync 直到 <c>IsPeerClosed</c> 置位，然后取消并等待。
	/// RFC 9147 §5.10 下对端 close_notify 不会自动 EOF，必须由调用方轮询状态。
	/// </summary>
	protected static async Task DrivePeerCloseAsync(DtlsTransport peer, CancellationToken cancellationToken)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		Task recv = Task.Run(async () =>
		{
			try
			{
				await peer.ReceiveAsync(new byte[1024], cts.Token);
			}
			catch (OperationCanceledException)
			{
			}
		}, cancellationToken);

		while (!peer.Session.IsPeerClosed)
		{
			await Task.Delay(10, cancellationToken);
		}

		cts.Cancel();
		await recv;
	}
}
