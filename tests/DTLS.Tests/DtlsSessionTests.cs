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
	[Fact]
	public void VerifyCertificate_ReturnsNone_WhenValid()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateEcdsaSelfSigned();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, "localhost");
		Assert.Equal(SslPolicyErrors.None, errors);
	}

	[Fact]
	public void VerifyCertificate_ReturnsNameMismatch_WhenHostnameWrong()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateEcdsaSelfSigned();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, "wrong-host.example.com");
		Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch));
	}

	[Fact]
	public void VerifyCertificate_ReturnsChainErrors_WhenEkuMismatch()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateWithClientAuthEkuOnly();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);
		chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));// ServerAuth

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, "localhost");
		Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
	}

	[Fact]
	public void VerifyCertificate_SkipsHostnameCheck_WhenTargetHostNull()
	{
		using X509Certificate2 cert = TestCertificateFactory.CreateEcdsaSelfSigned();
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(cert);

		SslPolicyErrors errors = DtlsSession.VerifyCertificate(chain, cert, null);
		Assert.Equal(SslPolicyErrors.None, errors);
	}

	[Fact]
	public void ClientOptions_HasExpectedDefaults()
	{
		DtlsClientOptions opts = new() { ServerName = "test" };
		Assert.Null(opts.ClientCertificate);
		Assert.Null(opts.RemoteCertificateValidation);
		Assert.Equal(TimeSpan.FromSeconds(15), opts.HandshakeTimeout);
		Assert.Equal(SslProtocols.None, opts.Version);
	}

	[Fact]
	public void ServerOptions_HasExpectedDefaults()
	{
		DtlsServerOptions opts = new() { Certificate = Cert };
		Assert.Null(opts.RemoteCertificateValidation);
		Assert.Equal(TimeSpan.FromSeconds(15), opts.HandshakeTimeout);
		Assert.Equal(SslProtocols.None, opts.Version);
		Assert.False(opts.RequireClientCertificate);
	}

	[Fact]
	public void CreateClient_Throws_WhenVersionUnsupported()
	{
		byte[] output = new byte[1];
		DtlsClientOptions options = new()
		{
			ServerName = "localhost",
			Version = (SslProtocols)0x0300
		};

		Assert.Throws<ArgumentOutOfRangeException>(() => DtlsSession.CreateClient(options, output));
	}

	[Fact]
	public void CreateClient_Throws_WhenVersionCombined()
	{
		byte[] output = new byte[1];
		DtlsClientOptions options = new()
		{
			ServerName = "localhost",
			Version = SslProtocols.Tls12 | SslProtocols.Tls13
		};

		Assert.Throws<ArgumentOutOfRangeException>(() => DtlsSession.CreateClient(options, output));
	}

	[Fact]
	public void CreateServer_Throws_WhenVersionUnsupported()
	{
		byte[] output = new byte[1];
		DtlsServerOptions options = new()
		{
			Certificate = Cert,
			Version = (SslProtocols)0x0300
		};

		Assert.Throws<ArgumentOutOfRangeException>(() => DtlsSession.CreateServer(options, output));
	}

	[Fact]
	public void CreateServer_Throws_WhenVersionCombined()
	{
		byte[] output = new byte[1];
		DtlsServerOptions options = new()
		{
			Certificate = Cert,
			Version = SslProtocols.Tls12 | SslProtocols.Tls13
		};

		Assert.Throws<ArgumentOutOfRangeException>(() => DtlsSession.CreateServer(options, output));
	}

	[Fact]
	public void CreateClient_ThrowsDtlsException_WhenOutputBufferTooSmall()
	{
		byte[] tinyOutput = new byte[1];
		DtlsClientOptions options = new()
		{
			ServerName = "localhost",
			RemoteCertificateValidation = (_, _, _) => true
		};

		DtlsException ex = Assert.Throws<DtlsException>(() => DtlsSession.CreateClient(options, tinyOutput));

		Assert.Equal(DtlsResult.BufferTooSmall, ex.ErrorCode);
		Assert.Contains("output buffer too small", ex.Message);
	}

	[Fact]
	public void FramedPacketEnumerator_EmptySpan_YieldsNothing()
	{
		int count = 0;

		foreach (ReadOnlySpan<byte> _ in new FramedPacketEnumerator(ReadOnlySpan<byte>.Empty))
		{
			++count;
		}

		Assert.Equal(0, count);
	}

	[Fact]
	public void FramedPacketEnumerator_SinglePacket()
	{
		byte[] framed = [3, 0, 0, 0, 0xAA, 0xBB, 0xCC];// len=3 LE u32, then 3 bytes
		List<byte[]> packets = [];

		foreach (ReadOnlySpan<byte> pkt in new FramedPacketEnumerator(framed))
		{
			packets.Add(pkt.ToArray());
		}

		Assert.Single(packets);
		Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, packets[0]);
	}

	[Fact]
	public void FramedPacketEnumerator_MultiplePackets()
	{
		byte[] framed = [2, 0, 0, 0, 0x01, 0x02, 1, 0, 0, 0, 0xFF];
		List<byte[]> packets = [];

		foreach (ReadOnlySpan<byte> pkt in new FramedPacketEnumerator(framed))
		{
			packets.Add(pkt.ToArray());
		}

		Assert.Equal(2, packets.Count);
		Assert.Equal(new byte[] { 0x01, 0x02 }, packets[0]);
		Assert.Equal(new byte[] { 0xFF }, packets[1]);
	}

	[Fact]
	public void FramedPacketEnumerator_TruncatedData_Stops()
	{
		byte[] framed = [5, 0, 0, 0, 0x01, 0x02];// claims 5 bytes but only 2 available
		int count = 0;

		foreach (ReadOnlySpan<byte> _ in new FramedPacketEnumerator(framed))
		{
			++count;
		}

		Assert.Equal(0, count);
	}

	[Fact]
	public void FramedPacketEnumerator_SingleByte_YieldsNothing()
	{
		byte[] framed = [0x01, 0x02, 0x03];// less than 4-byte header
		int count = 0;

		foreach (ReadOnlySpan<byte> _ in new FramedPacketEnumerator(framed))
		{
			++count;
		}

		Assert.Equal(0, count);
	}

	[Fact]
	public async Task SendAsync_ThrowsAfterDispose()
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await s.DisposeAsync();

		await using DtlsTransport _ = c;
		await Assert.ThrowsAsync<ObjectDisposedException>(() => s.SendAsync(new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());
	}

	[Fact]
	public async Task ReceiveAsync_ThrowsAfterDispose()
	{
		(DtlsTransport c, DtlsTransport s) = await HandshakePairAsync(TestContext.Current.CancellationToken);
		await c.DisposeAsync();

		await using DtlsTransport _ = s;
		await Assert.ThrowsAsync<ObjectDisposedException>(() => c.ReceiveAsync(new byte[1024], TestContext.Current.CancellationToken).AsTask());
	}
}
