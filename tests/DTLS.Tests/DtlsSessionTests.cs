using DTLS.Common;
using DTLS.Dtls;
using DTLS.Interop;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// ReSharper disable AccessToDisposedClosure

namespace DTLS.Tests;

public class DtlsSessionTests : DtlsTestBase
{
	[Test]
	[Arguments(false, (DtlsVersion)0, null, "minVersion")]
	[Arguments(true, null, (DtlsVersion)0, "maxVersion")]
	[Arguments(false, (DtlsVersion)3, null, "minVersion")]
	[Arguments(true, null, (DtlsVersion)3, "maxVersion")]
	[Arguments(false, null, (DtlsVersion)(-1), "maxVersion")]
	[Arguments(true, (DtlsVersion)(-1), null, "minVersion")]
	public async Task Create_RejectsUnknownVersionBounds(bool isServer, DtlsVersion? minVersion, DtlsVersion? maxVersion, string parameterName)
	{
		byte[] output = new byte[1];
		ArgumentOutOfRangeException? exception = await Assert.That
			(() => CreateSession(isServer, minVersion, maxVersion, output))
			.Throws<ArgumentOutOfRangeException>();
		await Assert.That(exception?.ParamName).IsEqualTo(parameterName);
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task Create_RejectsReversedVersionRange(bool isServer)
	{
		byte[] output = new byte[1];
		ArgumentException? exception = await Assert.That
			(() => CreateSession(isServer, DtlsVersion.Dtls13, DtlsVersion.Dtls12, output))
			.Throws<ArgumentException>();
		await Assert.That(exception?.ParamName).IsEqualTo("maxVersion");
	}

	[Test]
	[Arguments(3u, 0u)]
	[Arguments(0u, 3u)]
	[Arguments(uint.MaxValue, 0u)]
	[Arguments(0u, uint.MaxValue)]
	[Arguments(2u, 1u)]
	public async Task NativeCreate_RejectsInvalidVersionRange(uint minVersion, uint maxVersion)
	{
		DtlsSessionNewConfigNative config = new() { IsClient = 1, MinVersion = minVersion, MaxVersion = maxVersion };
		byte[] output = new byte[65536];
		DtlsCallResultNative result = NativeMethods.SessionNew(config, out SafeDtlsSessionHandle session, output, (nuint)output.Length);
		using (session)
		{
			await Assert.That(result.Code).IsEqualTo(DtlsResult.InvalidInput);
			await Assert.That(session.IsInvalid).IsTrue();
		}
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task Create_RejectsCertificateWithoutPrivateKey(bool isServer)
	{
		using X509Certificate2 publicCertificate = X509CertificateLoader.LoadCertificate(Cert.RawDataMemory.Span);
		byte[] output = new byte[65536];
		await Assert.That
			(() => isServer
				? DtlsSession.CreateServer(new DtlsServerOptions { Certificate = publicCertificate }, output)
				: DtlsSession.CreateClient
				(
					new DtlsClientOptions
					{
						ServerName = "localhost",
						ClientCertificate = publicCertificate
					}, output
				)
			)
			.Throws<CryptographicException>();
	}

	[Test]
	public async Task CreateClient_ThrowsDtlsException_WhenOutputBufferTooSmall()
	{
		byte[] tinyOutput = new byte[1];
		DtlsClientOptions options = new() { ServerName = "localhost" };

		DtlsException? ex = await Assert.That(() => DtlsSession.CreateClient(options, tinyOutput)).Throws<DtlsException>();
		await Assert.That(ex).IsNotNull();
		await Assert.That(ex.ErrorCode).IsEqualTo(DtlsResult.BufferTooSmall);
	}

	private (DtlsSession Session, DtlsOpResult Result) CreateSession(bool isServer, DtlsVersion? minVersion, DtlsVersion? maxVersion, Span<byte> output)
	{
		return isServer
			? DtlsSession.CreateServer
			(
				new DtlsServerOptions
				{
					Certificate = Cert,
					MinVersion = minVersion,
					MaxVersion = maxVersion
				}, output
			)
			: DtlsSession.CreateClient
			(
				new DtlsClientOptions
				{
					ServerName = "localhost",
					MinVersion = minVersion,
					MaxVersion = maxVersion
				}, output
			);
	}
}
