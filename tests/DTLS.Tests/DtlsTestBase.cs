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

	protected async Task<(DtlsTransport Client, DtlsTransport Server)> HandshakePairAsync(CancellationToken cancellationToken, DtlsVersion? version = null)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();
		DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				MinVersion = version,
				MaxVersion = version,
				RemoteCertificateValidation = (_, _, _) => true
			},
			cancellationToken
		);
		DtlsTransport? server = null;

		try
		{
			server = await DtlsTransport.CreateServerAsync
			(
				serverTransport,
				new DtlsServerOptions { Certificate = Cert, MinVersion = version, MaxVersion = version },
				cancellationToken
			);

			await Task.WhenAll
			(
				client.HandshakeAsync(cancellationToken).AsTask(),
				server.HandshakeAsync(cancellationToken).AsTask()
			);
			return (client, server);
		}
		catch
		{
			server?.Dispose();
			client.Dispose();
			throw;
		}
	}

	protected static (IDatagramTransport client, IDatagramTransport server) CreateTransportPair()
	{
		return ChannelDatagramTransport.CreatePair();
	}

	// DTLS 1.3 close_notify leaves ReceiveAsync waiting for reordered application data.
	protected static async Task DrivePeerCloseAsync(DtlsTransport peer, CancellationToken cancellationToken)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		Task recv = peer.ReceiveAsync(new byte[1024], cts.Token).AsTask();

		try
		{
			while (!peer.Session.IsPeerClosed)
			{
				await Task.Delay(10, cancellationToken);
			}
		}
		finally
		{
			await cts.CancelAsync();

			try
			{
				await recv;
			}
			catch (OperationCanceledException) when (cts.IsCancellationRequested)
			{
			}
		}
	}
}
