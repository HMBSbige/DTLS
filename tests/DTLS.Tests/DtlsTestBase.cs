using DTLS.Common;
using DTLS.Dtls;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

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
		Channel<byte[]> c2s = Channel.CreateUnbounded<byte[]>();
		Channel<byte[]> s2c = Channel.CreateUnbounded<byte[]>();
		return (
			new ChannelDatagramTransport(s2c.Reader, c2s.Writer),
			new ChannelDatagramTransport(c2s.Reader, s2c.Writer)
		);
	}
}
