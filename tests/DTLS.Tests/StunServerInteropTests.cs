using DTLS.Dtls;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace DTLS.Tests;

public class StunServerInteropTests
{
	private const int StunPort = 5349;

	[Theory]
	[InlineData("stun.wirecloud.de")]
	[InlineData("stun.hot-chilli.net")]
	public async Task Client_DtlsHandshake_WithStunServer(string stunHost)
	{
		Assert.SkipUnless
		(
			!string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase),
			"STUN interop tests are skipped when CI=true."
		);

		IPAddress[] addresses = await Dns.GetHostAddressesAsync(stunHost, AddressFamily.InterNetwork, TestContext.Current.CancellationToken);

		using UdpClient udp = new();
		UdpDatagramTransport transport = new(udp, new IPEndPoint(addresses.First(), StunPort));

		await using DtlsTransport client = await DtlsTransport.CreateClientAsync
		(
			transport,
			new DtlsClientOptions { ServerName = stunHost }
		);

		await client.HandshakeAsync(TestContext.Current.CancellationToken);

		Assert.False(client.Session.IsHandshaking);
		Assert.True(client.Session.Protocol is SslProtocols.Tls12 or SslProtocols.Tls13);
		Assert.NotNull(client.Session.RemoteCertificate);
	}
}
