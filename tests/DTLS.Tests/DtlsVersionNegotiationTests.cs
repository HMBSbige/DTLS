using DTLS.Common;
using DTLS.Dtls;
using System.Security.Authentication;

namespace DTLS.Tests;

public class DtlsVersionNegotiationTests : DtlsTestBase
{
	// ── Explicit Version: TLS 1.2 / TLS 1.3 ──────────────────────────────

	[Fact]
	public async Task ClientTls12_ServerTls12_Succeeds()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls12, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls12, server.Session.Protocol);
	}

	[Fact]
	public async Task ClientTls13_ServerTls13_Succeeds()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	[Fact]
	public async Task ClientTls12_ServerTls13_Fails()
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

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAnyAsync<Exception>(() => Task.WhenAll(clientHandshake, serverHandshake));
	}

	[Fact]
	public async Task ClientTls13_ServerTls12_Fails()
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

		Task clientHandshake = client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();
		Task serverHandshake = server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask();

		await Assert.ThrowsAnyAsync<Exception>(() => Task.WhenAll(clientHandshake, serverHandshake));
	}

	// ── Default Client Version Negotiation ───────────────────────────────

	[Fact]
	public async Task ClientDefault_ServerTls12_NegotiatesTls12()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls12, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls12, server.Session.Protocol);
	}

	[Fact]
	public async Task ClientDefault_ServerTls13_NegotiatesTls13()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	// ── Default Server Version Negotiation ───────────────────────────────

	[Fact]
	public async Task ClientTls12_ServerDefault_NegotiatesTls12()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls12, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls12, server.Session.Protocol);
	}

	[Fact]
	public async Task ClientTls13_ServerDefault_NegotiatesTls13()
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
			client.HandshakeAsync(TestContext.Current.CancellationToken).AsTask(),
			server.HandshakeAsync(TestContext.Current.CancellationToken).AsTask()
		);

		Assert.Equal(SslProtocols.Tls13, client.Session.Protocol);
		Assert.Equal(SslProtocols.Tls13, server.Session.Protocol);
	}

	// ── Both Default Version ─────────────────────────────────────────────

	[Fact]
	public async Task ClientDefault_ServerDefault_NegotiatesTls13()
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
}
