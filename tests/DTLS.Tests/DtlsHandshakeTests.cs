using DTLS.Common;
using DTLS.Dtls;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

namespace DTLS.Tests;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class DtlsHandshakeTests : DtlsTestBase
{
	[Test]
	public async Task Handshake_Completes(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task Handshake_ClientWithoutCert_ServerReceivesDefaultCert(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true,
				RemoteCertificateValidation = (_, _, _) => true
			}
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		Assert.NotNull(server.Session.RemoteCertificate);
		await Assert.That(server.Session.RemoteCertificate.SubjectName.Name).IsEqualTo("CN=DTLS Peer, O=DTLS");
		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task Handshake_ThrowsCertificateException_WhenNoValidationCallback(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions { ServerName = "localhost" }
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(clientHandshake).Throws<CertificateException>();
		await serverHandshake;
	}

	[Test]
	public async Task Handshake_TimesOut_WhenNoResponse(CancellationToken cancellationToken)
	{
		BlackHoleTransport blackHole = new();
		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			blackHole,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				HandshakeTimeout = TimeSpan.FromMilliseconds(500)
			}
		);

		await Assert.That(async () => await client.HandshakeAsync(cancellationToken)).Throws<DtlsTimeoutException>();
	}

	[Test]
	public async Task Handshake_CancelledByToken(CancellationToken cancellationToken)
	{
		BlackHoleTransport blackHole = new();
		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			blackHole,
			new DtlsClientOptions { ServerName = "localhost" }
		);

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		cts.CancelAfter(TimeSpan.FromMilliseconds(200));

		await Assert.That(async () => await client.HandshakeAsync(cts.Token)).Throws<TaskCanceledException>();
	}

	[Test]
	public async Task Handshake_Completes_WithClientCertificate(CancellationToken cancellationToken)
	{
		using X509Certificate2 clientCert = TestCertificateFactory.CreateEcdsaSelfSigned();
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				ClientCertificate = clientCert,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(clientCert, "localhost", cert, chain, errors)
			}
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task Handshake_ClientValidationCallback_AcceptsServerIpCertificate(CancellationToken cancellationToken)
	{
		string loopbackIp = IPAddress.Loopback.ToString();
		using X509Certificate2 serverIpCert = TestCertificateFactory.CreateEcdsaSelfSignedWithIpAddress(loopbackIp);
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = loopbackIp,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(serverIpCert, loopbackIp, cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverIpCert }
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task Handshake_ClientValidationCallback_RejectsServerIpCertificate_ThrowsException(CancellationToken cancellationToken)
	{
		const string presentedIp = "127.0.0.1";
		const string expectedIp = "127.0.0.2";
		using X509Certificate2 serverIpCert = TestCertificateFactory.CreateEcdsaSelfSignedWithIpAddress(presentedIp);
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = presentedIp,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(serverIpCert, expectedIp, cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverIpCert }
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(clientHandshake).Throws<CertificateException>();
		await serverHandshake;
	}

	[Test]
	public async Task Handshake_ServerValidationCallback_AcceptsClientIpCertificate(CancellationToken cancellationToken)
	{
		const string clientIp = "127.0.0.1";
		using X509Certificate2 clientIpCert = TestCertificateFactory.CreateEcdsaSelfSignedWithIpAddress(clientIp);
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				ClientCertificate = clientIpCert,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(clientIpCert, clientIp, cert, chain, errors)
			}
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task Handshake_ServerValidationCallback_RejectsClientIpCertificate_ThrowsException(CancellationToken cancellationToken)
	{
		const string presentedClientIp = "127.0.0.1";
		const string expectedClientIp = "127.0.0.2";
		using X509Certificate2 clientIpCert = TestCertificateFactory.CreateEcdsaSelfSignedWithIpAddress(presentedClientIp);
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				ClientCertificate = clientIpCert,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(clientIpCert, expectedClientIp, cert, chain, errors)
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(serverHandshake).Throws<CertificateException>();
		await clientHandshake;
	}

	[Test]
	public async Task Handshake_ServerThrows_WhenClientCertReceivedWithoutValidationCallback(CancellationToken cancellationToken)
	{
		using X509Certificate2 clientCert = TestCertificateFactory.CreateEcdsaSelfSigned();
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				ClientCertificate = clientCert,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(serverHandshake).Throws<CertificateException>();
		await clientHandshake;
	}

	[Test]
	public async Task Handshake_ServerValidationCallback_RejectsCert_ThrowsException(CancellationToken cancellationToken)
	{
		SslPolicyErrors receivedErrors = SslPolicyErrors.None;
		bool? chainBuildResult = null;
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				ClientCertificate = Cert,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RemoteCertificateValidation = (cert, chain, errors) =>
				{
					Assert.NotNull(cert);
					Assert.NotNull(chain);
					receivedErrors = errors;
					chainBuildResult = chain.Build(cert);
					return false;
				}
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(serverHandshake).Throws<CertificateException>();
		await clientHandshake;

		await Assert.That(receivedErrors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
		await Assert.That(chainBuildResult).IsFalse();
	}

	[Test]
	public async Task Handshake_ServerHasCallback_NotRequireClientCertificate(CancellationToken cancellationToken)
	{
		X509Certificate2? capturedCert = null;
		X509Chain? capturedChain = null;
		SslPolicyErrors capturedErrors = SslPolicyErrors.None;
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				// Server has callback but RequireClientCertificate=false.
				// Like SslStream, the server still requests a client cert,
				// so the callback receives whatever the client provided.
				RemoteCertificateValidation = (cert, chain, errors) =>
				{
					capturedCert = cert;
					capturedChain = chain;
					capturedErrors = errors;
					return errors is SslPolicyErrors.None;
				}
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(serverHandshake).Throws<CertificateException>();
		await clientHandshake;

		await Assert.That(capturedCert).IsNotNull();
		await Assert.That(capturedCert.MatchesHostname("wrong.example.com")).IsFalse();
		await Assert.That(capturedChain).IsNotNull();
		await Assert.That(capturedErrors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
	}

	[Test]
	public async Task Handshake_Completes_DespitePacketLoss(CancellationToken cancellationToken)
	{
		Channel<byte[]> c2s = Channel.CreateUnbounded<byte[]>();
		Channel<byte[]> s2c = Channel.CreateUnbounded<byte[]>();

		ChannelDatagramTransport clientTransport = new(s2c.Reader, c2s.Writer);
		DropFirstSendTransport serverTransport = new
		(
			new ChannelDatagramTransport(c2s.Reader, s2c.Writer)
		);

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				HandshakeTimeout = TimeSpan.FromSeconds(15),
				RemoteCertificateValidation = (cert, _, _) => cert is not null && cert.MatchesHostname("localhost")
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task ConnectionInfo_PopulatedAfterHandshake(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		await Assert.That(c.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
		await Assert.That(c.Session.RemoteCertificate).IsNotNull();

		await Assert.That(s.Session.Protocol).IsEqualTo(SslProtocols.Tls13);
	}

	[Test]
	public async Task Handshake_CallbackReceivesNameMismatch(CancellationToken cancellationToken)
	{
		SslPolicyErrors receivedErrors = SslPolicyErrors.None;
		X509Certificate2? receivedCert = null;
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "wrong.example.com",
				RemoteCertificateValidation = (cert, _, errors) =>
				{
					receivedErrors = errors;
					receivedCert = cert;
					return true;
				}
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert }
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(receivedCert).IsNotNull();
		await Assert.That(receivedCert.MatchesHostname("wrong.example.com")).IsFalse();
		await Assert.That(receivedErrors).HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
	}

	[Test]
	public async Task Handshake_ClientRejectsServerCert_WithClientAuthEkuOnly(CancellationToken cancellationToken)
	{
		SslPolicyErrors capturedErrors = SslPolicyErrors.None;
		X509ChainStatus[]? capturedChainStatus = null;
		using X509Certificate2 serverCert = TestCertificateFactory.CreateWithClientAuthEkuOnly();
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, chain, errors) =>
				{
					Assert.NotNull(cert);
					Assert.NotNull(chain);
					capturedErrors = errors;
					capturedChainStatus = chain.ChainStatus;
					return errors is SslPolicyErrors.None;
				}
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverCert }
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(clientHandshake).Throws<CertificateException>();
		await serverHandshake;

		await Assert.That(capturedErrors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
		await Assert.That(capturedChainStatus).Any(s => s.Status == X509ChainStatusFlags.NotValidForUsage);
	}

	[Test]
	public async Task Handshake_ServerRejectsClientCert_WithServerAuthEkuOnly(CancellationToken cancellationToken)
	{
		SslPolicyErrors capturedErrors = SslPolicyErrors.None;
		X509ChainStatus[]? capturedChainStatus = null;
		using X509Certificate2 clientCert = TestCertificateFactory.CreateWithServerAuthEkuOnly();
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				ClientCertificate = clientCert,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true,
				RemoteCertificateValidation = (cert, chain, errors) =>
				{
					Assert.NotNull(cert);
					Assert.NotNull(chain);
					capturedErrors = errors;
					capturedChainStatus = chain.ChainStatus;
					return errors is SslPolicyErrors.None;
				}
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(serverHandshake).Throws<CertificateException>();
		await clientHandshake;

		await Assert.That(capturedErrors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
		await Assert.That(capturedChainStatus).Any(s => s.Status == X509ChainStatusFlags.NotValidForUsage);
	}
}
