using DTLS.Dtls;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace DTLS.Tests;

public class StunServerInteropTests
{
	private const int StunPort = 5349;

	[Test]
	[Arguments("stun.wirecloud.de")]
	[Arguments("stun.hot-chilli.net")]
	public async Task Client_DtlsHandshake_WithStunServer(string stunHost, CancellationToken cancellationToken)
	{
		Skip.When(bool.TryParse(Environment.GetEnvironmentVariable("CI"), out bool isCi) && isCi, "STUN interop tests are skipped when CI=true.");

		IPAddress[] addresses = await Dns.GetHostAddressesAsync(stunHost, AddressFamily.InterNetwork, cancellationToken);

		using UdpClient udp = new();
		UdpDatagramTransport transport = new(udp, new IPEndPoint(addresses.First(), StunPort));

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			transport,
			new DtlsClientOptions { ServerName = stunHost }
		);

		await client.HandshakeAsync(cancellationToken);

		await Assert.That(client.Session.IsHandshaking).IsFalse();
		await Assert.That(client.Session.Protocol is SslProtocols.Tls12 or SslProtocols.Tls13).IsTrue();
		await Assert.That(client.Session.RemoteCertificate).IsNotNull();
	}
}
