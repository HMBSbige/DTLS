using DTLS.Common;
using DTLS.Dtls;
using DTLS.Interop;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

public class DtlsSessionTests : DtlsTestBase
{
	[Test]
	public async Task VerifyCertificate_ReturnsNone_WhenValid()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateEcdsaSelfSigned();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, "localhost");
		await Assert.That(errors).IsEqualTo(SslPolicyErrors.None);
	}

	[Test]
	public async Task VerifyCertificate_ReturnsNameMismatch_WhenHostnameWrong()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateEcdsaSelfSigned();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, "wrong-host.example.com");
		await Assert.That(errors).HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
	}

	[Test]
	public async Task VerifyCertificate_ReturnsChainErrors_WhenEkuMismatch()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateWithClientAuthEkuOnly();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);
		chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));// ServerAuth

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, "localhost");
		await Assert.That(errors).HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
	}

	[Test]
	public async Task VerifyCertificate_SkipsHostnameCheck_WhenTargetHostNull()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateEcdsaSelfSigned();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, null);
		await Assert.That(errors).IsEqualTo(SslPolicyErrors.None);
	}

	[Test]
	public async Task ClientOptions_HasExpectedDefaults()
	{
		DtlsClientOptions opts = new() { ServerName = "test" };
		await Assert.That(opts.ClientCertificate).IsNull();
		await Assert.That(opts.RemoteCertificateValidation).IsNull();
		await Assert.That(opts.HandshakeTimeout).IsEqualTo(TimeSpan.FromSeconds(15));
		await Assert.That(opts.Version).IsEqualTo(SslProtocols.None);
	}

	[Test]
	public async Task ServerOptions_HasExpectedDefaults()
	{
		DtlsServerOptions opts = new() { Certificate = Cert };
		await Assert.That(opts.RemoteCertificateValidation).IsNull();
		await Assert.That(opts.HandshakeTimeout).IsEqualTo(TimeSpan.FromSeconds(15));
		await Assert.That(opts.Version).IsEqualTo(SslProtocols.None);
		await Assert.That(opts.RequireClientCertificate).IsFalse();
	}

	[Test]
	public async Task CreateClient_Throws_WhenVersionUnsupported()
	{
		byte[] output = new byte[1];
		DtlsClientOptions options = new()
		{
			ServerName = "localhost",
			Version = (SslProtocols)0x0300
		};

		await Assert.That(() => DtlsSession.CreateClient(options, output)).Throws<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task CreateClient_Throws_WhenVersionCombined()
	{
		byte[] output = new byte[1];
		DtlsClientOptions options = new()
		{
			ServerName = "localhost",
			Version = SslProtocols.Tls12 | SslProtocols.Tls13
		};

		await Assert.That(() => DtlsSession.CreateClient(options, output)).Throws<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task CreateServer_Throws_WhenVersionUnsupported()
	{
		byte[] output = new byte[1];
		DtlsServerOptions options = new()
		{
			Certificate = Cert,
			Version = (SslProtocols)0x0300
		};

		await Assert.That(() => DtlsSession.CreateServer(options, output)).Throws<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task CreateServer_Throws_WhenVersionCombined()
	{
		byte[] output = new byte[1];
		DtlsServerOptions options = new()
		{
			Certificate = Cert,
			Version = SslProtocols.Tls12 | SslProtocols.Tls13
		};

		await Assert.That(() => DtlsSession.CreateServer(options, output)).Throws<ArgumentOutOfRangeException>();
	}

	[Test]
	public async Task CreateClient_ThrowsDtlsException_WhenOutputBufferTooSmall()
	{
		byte[] tinyOutput = new byte[1];
		DtlsClientOptions options = new()
		{
			ServerName = "localhost",
			RemoteCertificateValidation = (_, _, _) => true
		};

		DtlsException? ex = await Assert.That(() => DtlsSession.CreateClient(options, tinyOutput)).Throws<DtlsException>();
		await Assert.That(ex).IsNotNull();
		await Assert.That(ex.ErrorCode).IsEqualTo(DtlsResult.BufferTooSmall);
		await Assert.That(ex.Message).Contains("output buffer too small");
	}

	[Test]
	public async Task FramedPacketEnumerator_EmptySpan_YieldsNothing()
	{
		int count = 0;

		foreach (ReadOnlySpan<byte> _ in new FramedPacketEnumerator(ReadOnlySpan<byte>.Empty))
		{
			++count;
		}

		await Assert.That(count).IsEqualTo(0);
	}

	[Test]
	public async Task FramedPacketEnumerator_SinglePacket()
	{
		byte[] framed = [3, 0, 0, 0, 0xAA, 0xBB, 0xCC];// len=3 LE u32, then 3 bytes
		List<byte[]> packets = [];

		foreach (ReadOnlySpan<byte> pkt in new FramedPacketEnumerator(framed))
		{
			packets.Add(pkt.ToArray());
		}

		await Assert.That(packets).Count().IsEqualTo(1);
		await Assert.That(packets[0].AsSpan().SequenceEqual(new byte[] { 0xAA, 0xBB, 0xCC })).IsTrue();
	}

	[Test]
	public async Task FramedPacketEnumerator_MultiplePackets()
	{
		byte[] framed = [2, 0, 0, 0, 0x01, 0x02, 1, 0, 0, 0, 0xFF];
		List<byte[]> packets = [];

		foreach (ReadOnlySpan<byte> pkt in new FramedPacketEnumerator(framed))
		{
			packets.Add(pkt.ToArray());
		}

		await Assert.That(packets).Count().IsEqualTo(2);
		await Assert.That(packets[0].AsSpan().SequenceEqual(new byte[] { 0x01, 0x02 })).IsTrue();
		await Assert.That(packets[1].AsSpan().SequenceEqual(new byte[] { 0xFF })).IsTrue();
	}

	[Test]
	public async Task FramedPacketEnumerator_TruncatedData_Stops()
	{
		byte[] framed = [5, 0, 0, 0, 0x01, 0x02];// claims 5 bytes but only 2 available
		int count = 0;

		foreach (ReadOnlySpan<byte> _ in new FramedPacketEnumerator(framed))
		{
			++count;
		}

		await Assert.That(count).IsEqualTo(0);
	}

	[Test]
	public async Task FramedPacketEnumerator_SingleByte_YieldsNothing()
	{
		byte[] framed = [0x01, 0x02, 0x03];// less than 4-byte header
		int count = 0;

		foreach (ReadOnlySpan<byte> _ in new FramedPacketEnumerator(framed))
		{
			++count;
		}

		await Assert.That(count).IsEqualTo(0);
	}

	[Test]
	public async Task SendAsync_ThrowsAfterDispose(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await s.DisposeAsync();

		await using DtlsTransport _ = c;
		await Assert.That(async () => await s.SendAsync(new byte[] { 1 }, cancellationToken)).Throws<ObjectDisposedException>();
	}

	[Test]
	public async Task ReceiveAsync_ThrowsAfterDispose(CancellationToken cancellationToken)
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(cancellationToken);
		await c.DisposeAsync();

		await using DtlsTransport _ = s;
		await Assert.That(async () => await c.ReceiveAsync(new byte[1024], cancellationToken)).Throws<ObjectDisposedException>();
	}
}
