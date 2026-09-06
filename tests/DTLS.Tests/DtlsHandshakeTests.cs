using DTLS.Common;
using DTLS.Dtls;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class DtlsHandshakeTests : DtlsTestBase
{
	[Test]
	public async Task Handshake_ClientValidationCallback_BuildsWithExplicitIntermediate(CancellationToken cancellationToken)
	{
		bool validatedChain = false;
		(X509Certificate2 root, X509Certificate2 intermediate, X509Certificate2 leaf) = TestCertificateFactory.CreateEcdsaCertificateChain();

		using (root)
		using (intermediate)
		using (leaf)
		{
			(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

			await using DtlsTransport client = await DtlsTransport.CreateClientAsync
			(
				clientTransport,
				new DtlsClientOptions
				{
					ServerName = "localhost",
					RemoteCertificateValidation = (cert, chain, _) =>
					{
						if (cert is null || chain is null)
						{
							return false;
						}

						return validatedChain = TestCertificateFactory.BuildChainWithExplicitIntermediate(root, intermediate, cert);
					}
				},
				cancellationToken
			);
			await using DtlsTransport server = await DtlsTransport.CreateServerAsync
			(
				serverTransport,
				new DtlsServerOptions { Certificate = leaf },
				cancellationToken
			);

			await Task.WhenAll
			(
				client.HandshakeAsync(cancellationToken).AsTask(),
				server.HandshakeAsync(cancellationToken).AsTask()
			);

			await Assert.That(validatedChain).IsTrue();
		}
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
			},
			cancellationToken
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
			new DtlsClientOptions { ServerName = "localhost" },
			cancellationToken
		);

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		cts.CancelAfter(TimeSpan.FromMilliseconds(200));

		await Assert.That(async () => await client.HandshakeAsync(cts.Token)).Throws<TaskCanceledException>();
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
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverIpCert },
			cancellationToken
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(DtlsVersion.Dtls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(DtlsVersion.Dtls13);
	}

	[Test]
	public async Task Handshake_ServerValidationCallback_AcceptsClientIpCertificate(CancellationToken cancellationToken)
	{
		const string clientIp = "127.0.0.1";
		bool validatedClientCertificate = false;
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
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true,
				RemoteCertificateValidation = (cert, chain, errors) => validatedClientCertificate = TestCertificateFactory.ValidateSelfSignedAndMatchHostname(clientIpCert, clientIp, cert, chain, errors)
			},
			cancellationToken
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(validatedClientCertificate).IsTrue();
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
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RequireClientCertificate = true
			},
			cancellationToken
		);

		await AssertCertificateRejectedAsync(server, client, cancellationToken);
	}

	[Test]
	public async Task Handshake_ServerCallback_RequestsAndValidatesOptionalClientCertificate(CancellationToken cancellationToken)
	{
		bool receivedCertificate = false;
		bool receivedChain = false;
		SslPolicyErrors capturedErrors = SslPolicyErrors.None;
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				RemoteCertificateValidation = (cert, chain, errors) =>
				{
					receivedCertificate = cert is not null;
					receivedChain = chain is not null;
					capturedErrors = errors;
					return errors is SslPolicyErrors.None;
				}
			},
			cancellationToken
		);

		await AssertCertificateRejectedAsync(server, client, cancellationToken);

		await Assert.That(receivedCertificate).IsTrue();
		await Assert.That(receivedChain).IsTrue();
		await Assert.That(capturedErrors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
	}

	[Test]
	public async Task Handshake_Completes_DespitePacketLoss(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport rawServerTransport) = CreateTransportPair();
		DropFirstSendTransport serverTransport = new(rawServerTransport);

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, _, _) => cert is not null && cert.MatchesHostname("localhost")
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = Cert },
			cancellationToken
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(DtlsVersion.Dtls13);
		await Assert.That(server.Session.Protocol).IsEqualTo(DtlsVersion.Dtls13);
	}

	[Test]
	[Arguments("wrong.example.com", false)]
	[Arguments("127.0.0.2", true)]
	public async Task Handshake_CallbackReceivesNameMismatch(string serverName, bool useIpCertificate, CancellationToken cancellationToken)
	{
		SslPolicyErrors receivedErrors = SslPolicyErrors.None;
		bool receivedCertificate = false;
		using X509Certificate2 serverCertificate = useIpCertificate
			? TestCertificateFactory.CreateEcdsaSelfSignedWithIpAddress("127.0.0.1")
			: TestCertificateFactory.CreateEcdsaSelfSigned();
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = serverName,
				RemoteCertificateValidation = (cert, _, errors) =>
				{
					receivedErrors = errors;
					receivedCertificate = cert is not null;
					return true;
				}
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverCertificate },
			cancellationToken
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(receivedCertificate).IsTrue();
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
			},
			cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions { Certificate = serverCert },
			cancellationToken
		);

		await AssertCertificateRejectedAsync(client, server, cancellationToken);

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
			},
			cancellationToken
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
			},
			cancellationToken
		);

		await AssertCertificateRejectedAsync(server, client, cancellationToken);

		await Assert.That(capturedErrors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
		await Assert.That(capturedChainStatus).Any(s => s.Status == X509ChainStatusFlags.NotValidForUsage);
	}

	private static async Task AssertCertificateRejectedAsync(DtlsTransport rejected, DtlsTransport peer, CancellationToken cancellationToken)
	{
		using CancellationTokenSource peerCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		Task peerHandshake = peer.HandshakeAsync(peerCancellation.Token).AsTask();

		try
		{
			await Assert.That(async () => await rejected.HandshakeAsync(cancellationToken)).Throws<CertificateException>();
		}
		finally
		{
			await peerCancellation.CancelAsync();

			try
			{
				await peerHandshake;
			}
			catch (OperationCanceledException) when (peerCancellation.IsCancellationRequested)
			{
			}
		}
	}
}
