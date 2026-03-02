using DTLS.Common;
using DTLS.Dtls;
using System.Security.Authentication;

namespace DTLS.Tests;

public class DtlsVersionNegotiationTests : DtlsTestBase
{
	// ── Explicit Version: TLS 1.2 / TLS 1.3 ──────────────────────────────

	[Test]
	public async Task ClientTls12_ServerTls12_Succeeds(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls12,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				Version = SslProtocols.Tls12
			}
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls12);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls12);
	}

	[Test]
	public async Task ClientTls13_ServerTls13_Succeeds(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls13,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				Version = SslProtocols.Tls13
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
	public async Task ClientTls12_ServerTls13_Fails(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls12,
				HandshakeTimeout = TimeSpan.FromSeconds(3),
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				Version = SslProtocols.Tls13,
				HandshakeTimeout = TimeSpan.FromSeconds(3)
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(Task.WhenAll(clientHandshake, serverHandshake)).Throws<Exception>();
	}

	[Test]
	public async Task ClientTls13_ServerTls12_Fails(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls13,
				HandshakeTimeout = TimeSpan.FromSeconds(3),
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport,
			new DtlsServerOptions
			{
				Certificate = Cert,
				Version = SslProtocols.Tls12,
				HandshakeTimeout = TimeSpan.FromSeconds(3)
			}
		);

		Task clientHandshake = client.HandshakeAsync(cancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(cancellationToken).AsTask();

		await Assert.That(Task.WhenAll(clientHandshake, serverHandshake)).Throws<Exception>();
	}

	// ── Default Client Version Negotiation ───────────────────────────────

	[Test]
	public async Task ClientDefault_ServerTls12_NegotiatesTls12(CancellationToken cancellationToken)
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
				Version = SslProtocols.Tls12
			}
		);

		await Task.WhenAll
		(
			client.HandshakeAsync(cancellationToken).AsTask(),
			server.HandshakeAsync(cancellationToken).AsTask()
		);

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls12);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls12);
	}

	[Test]
	public async Task ClientDefault_ServerTls13_NegotiatesTls13(CancellationToken cancellationToken)
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
				Version = SslProtocols.Tls13
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

	// ── Default Server Version Negotiation ───────────────────────────────

	[Test]
	public async Task ClientTls12_ServerDefault_NegotiatesTls12(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls12,
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

		await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls12);
		await Assert.That(server.Session.Protocol).IsEqualTo(SslProtocols.Tls12);
	}

	[Test]
	public async Task ClientTls13_ServerDefault_NegotiatesTls13(CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport,
			new DtlsClientOptions
			{
				ServerName = "localhost",
				Version = SslProtocols.Tls13,
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

	// ── Both Default Version ─────────────────────────────────────────────

	[Test]
	public async Task ClientDefault_ServerDefault_NegotiatesTls13(CancellationToken cancellationToken)
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
}
