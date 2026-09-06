using DTLS.Common;
using DTLS.Dtls;

namespace DTLS.Tests;

public class DtlsVersionNegotiationTests : DtlsTestBase
{
	[Test]
	[Arguments(null, null, null, null, DtlsVersion.Dtls13)]
	[Arguments(null, DtlsVersion.Dtls12, null, null, DtlsVersion.Dtls12)]
	[Arguments(null, null, null, DtlsVersion.Dtls12, DtlsVersion.Dtls12)]
	[Arguments(DtlsVersion.Dtls13, null, null, null, DtlsVersion.Dtls13)]
	[Arguments(null, null, DtlsVersion.Dtls13, null, DtlsVersion.Dtls13)]
	[Arguments(DtlsVersion.Dtls12, null, null, null, DtlsVersion.Dtls13)]
	[Arguments(null, DtlsVersion.Dtls13, DtlsVersion.Dtls12, DtlsVersion.Dtls12, DtlsVersion.Dtls12)]
	[Arguments(DtlsVersion.Dtls12, DtlsVersion.Dtls13, DtlsVersion.Dtls12, DtlsVersion.Dtls13, DtlsVersion.Dtls13)]
	public async Task CompatibleRanges_NegotiateExpectedVersion(DtlsVersion? clientMin, DtlsVersion? clientMax, DtlsVersion? serverMin, DtlsVersion? serverMax, DtlsVersion expectedVersion, CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();
		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport, new DtlsClientOptions
			{
				ServerName = "localhost",
				MinVersion = clientMin,
				MaxVersion = clientMax,
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSignedAndMatchHostname(Cert, "localhost", cert, chain, errors)
			}, cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport, new DtlsServerOptions
			{
				Certificate = Cert,
				MinVersion = serverMin,
				MaxVersion = serverMax
			}, cancellationToken
		);

		await Task.WhenAll(client.HandshakeAsync(cancellationToken).AsTask(), server.HandshakeAsync(cancellationToken).AsTask());

		await Assert.That(client.Session.Protocol).IsEqualTo(expectedVersion);
		await Assert.That(server.Session.Protocol).IsEqualTo(expectedVersion);
	}

	[Test]
	[Arguments(DtlsVersion.Dtls13, null, null, DtlsVersion.Dtls12)]
	[Arguments(null, DtlsVersion.Dtls12, DtlsVersion.Dtls13, null)]
	public async Task NonOverlappingRanges_RejectHandshake(DtlsVersion? clientMin, DtlsVersion? clientMax, DtlsVersion? serverMin, DtlsVersion? serverMax, CancellationToken cancellationToken)
	{
		(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = CreateTransportPair();
		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			clientTransport, new DtlsClientOptions
			{
				ServerName = "localhost",
				MinVersion = clientMin,
				MaxVersion = clientMax,
				HandshakeTimeout = TimeSpan.FromSeconds(3),
				RemoteCertificateValidation = (_, _, _) => true
			}, cancellationToken
		);
		await using DtlsTransport server = await DtlsTransport.CreateServerAsync
		(
			serverTransport, new DtlsServerOptions
			{
				Certificate = Cert,
				MinVersion = serverMin,
				MaxVersion = serverMax,
				HandshakeTimeout = TimeSpan.FromSeconds(3)
			}, cancellationToken
		);

		Task handshake = Task.WhenAll(client.HandshakeAsync(cancellationToken).AsTask(), server.HandshakeAsync(cancellationToken).AsTask());
		await Assert.That(handshake).Throws<DtlsException>();
		await Assert.That(client.Session.Protocol).IsNull();
		await Assert.That(server.Session.Protocol).IsNull();
	}
}
