using DTLS.Common;
using DTLS.Dtls;
using DTLS.Tests;
using System.Security.Cryptography.X509Certificates;

using X509Certificate2 certificate = TestCertificateFactory.CreateEcdsaSelfSigned();
(IDatagramTransport clientTransport, IDatagramTransport serverTransport) = ChannelDatagramTransport.CreatePair();

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
	serverTransport,
	new DtlsServerOptions { Certificate = certificate }
);

using CancellationTokenSource cancellationTokenSource = new(TimeSpan.FromSeconds(15));
await Task.WhenAll
(
	client.HandshakeAsync(cancellationTokenSource.Token).AsTask(),
	server.HandshakeAsync(cancellationTokenSource.Token).AsTask()
);

byte[] expected = "NativeAOT DTLS smoke test"u8.ToArray();
await client.SendAsync(expected, cancellationTokenSource.Token);

byte[] actual = new byte[expected.Length];
int bytesRead = await server.ReceiveAsync(actual, cancellationTokenSource.Token);

if (bytesRead != expected.Length || !actual.AsSpan(0, bytesRead).SequenceEqual(expected))
{
	throw new InvalidOperationException("DTLS NativeAOT data transfer failed.");
}

Console.WriteLine("DTLS NativeAOT handshake and data transfer succeeded.");
