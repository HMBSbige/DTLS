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
	[Fact]
	public async Task Handshake_Completes()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task Handshake_ClientWithoutCert_ServerReceivesDefaultCert()
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
				RemoteCertificateValidation = (cert, chain, errors) =>
				{
					Assert.NotNull(cert);
					Assert.NotNull(chain);
					Assert.Equal("CN=DTLS Peer, O=DTLS", cert.SubjectName.Name);
					return true;
				}
			}
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task Handshake_ThrowsCertificateException_WhenNoValidationCallback()
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

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => clientHandshake);
		await serverHandshake;
	}

	[Fact]
	public async Task Handshake_TimesOut_WhenNoResponse()
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

		await Assert.ThrowsAsync<DtlsTimeoutException>(() => client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask());
	}

	[Fact]
	public async Task Handshake_CancelledByToken()
	{
		BlackHoleTransport blackHole = new();
		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			blackHole,
			new DtlsClientOptions
			{
				ServerName = "localhost"
			}
		);

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
		cts.CancelAfter(TimeSpan.FromMilliseconds(200));

		await Assert.ThrowsAsync<TaskCanceledException>(() => client.HandshakeAsync(cts.Token).AsTask());
	}

	[Fact]
	public async Task Handshake_Completes_WithClientCertificate()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task Handshake_ClientValidationCallback_AcceptsServerIpCertificate()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task Handshake_ClientValidationCallback_RejectsServerIpCertificate_ThrowsException()
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

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => clientHandshake);
		await serverHandshake;
	}

	[Fact]
	public async Task Handshake_ServerValidationCallback_AcceptsClientIpCertificate()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task Handshake_ServerValidationCallback_RejectsClientIpCertificate_ThrowsException()
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

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => serverHandshake);
		await clientHandshake;
	}

	[Fact]
	public async Task Handshake_ServerThrows_WhenClientCertReceivedWithoutValidationCallback()
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

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => serverHandshake);
		await clientHandshake;
	}

	[Fact]
	public async Task Handshake_ServerValidationCallback_RejectsCert_ThrowsException()
	{
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
					Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
					Assert.False(chain.Build(cert));
					return false;
				}
			}
		);

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => serverHandshake);
		await clientHandshake;
	}

	[Fact]
	public async Task Handshake_ServerHasCallback_NotRequireClientCertificate()
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
				RemoteCertificateValidation = (cert, chains, errors) =>
				{
					// Server has callback but RequireClientCertificate=false.
					// Like SslStream, the server still requests a client cert,
					// so the callback receives whatever the client provided.
					Assert.NotNull(cert);
					Assert.False(cert.MatchesHostname("wrong.example.com"));
					Assert.NotNull(chains);
					Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
					return errors is SslPolicyErrors.None;
				}
			}
		);

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => serverHandshake);
		await clientHandshake;
	}

	[Fact]
	public async Task Handshake_Completes_DespitePacketLoss()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task ConnectionInfo_PopulatedAfterHandshake()
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await using DtlsTransport _ = c;
		await using DtlsTransport __ = s;

		Assert.Equal(SslProtocols.Tls13, c.Session.Protocol);
		Assert.NotEqual(default, c.Session.CipherSuite);
		Assert.NotNull(c.Session.RemoteCertificate);

		Assert.Equal(SslProtocols.Tls13, s.Session.Protocol);
		Assert.NotEqual(default, s.Session.CipherSuite);
	}

	[Fact]
	public async Task Handshake_CallbackReceivesNameMismatch()
	{
		SslPolicyErrors receivedErrors = SslPolicyErrors.None;
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
					Assert.NotNull(cert);
					Assert.False(cert.MatchesHostname("wrong.example.com"));
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.True(receivedErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch));
	}

	[Fact]
	public async Task Handshake_ClientRejectsServerCert_WithClientAuthEkuOnly()
	{
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
					Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
					Assert.Contains(chain.ChainStatus, s => s.Status == X509ChainStatusFlags.NotValidForUsage);
					return errors is SslPolicyErrors.None;
				}
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverCert }
		);

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => clientHandshake);
		await serverHandshake;
	}

	[Fact]
	public async Task Handshake_ServerRejectsClientCert_WithServerAuthEkuOnly()
	{
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
					Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
					Assert.Contains(chain.ChainStatus, s => s.Status == X509ChainStatusFlags.NotValidForUsage);
					return errors is SslPolicyErrors.None;
				}
			}
		);

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAsync<CertificateException>(() => serverHandshake);
		await clientHandshake;
	}
}
