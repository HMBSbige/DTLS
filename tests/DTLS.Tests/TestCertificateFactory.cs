using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

internal static partial class TestCertificateFactory
{
	/// <summary>Root 与 Intermediate 仅含公钥（信任锚用途）；Leaf 含可导出私钥，可用作服务端证书。</summary>
	public static (X509Certificate2 Root, X509Certificate2 Intermediate, X509Certificate2 Leaf) CreateEcdsaCertificateChain()
	{
		DateTimeOffset now = DateTimeOffset.UtcNow;
		DateTimeOffset notBefore = now.AddMinutes(-1);
		DateTimeOffset notAfter = now.AddDays(1);

		using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest rootRequest = CreateCaRequest("CN=DTLS Test Root", rootKey, hasPathLengthConstraint: false);
		using X509Certificate2 rootWithKey = rootRequest.CreateSelfSigned(notBefore, notAfter);

		using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest intermediateRequest = CreateCaRequest("CN=DTLS Test Intermediate", intermediateKey, hasPathLengthConstraint: true);
		using X509Certificate2 intermediatePublic = intermediateRequest.Create(rootWithKey, notBefore, notAfter, CreateSerialNumber());
		using X509Certificate2 intermediateWithKey = intermediatePublic.CopyWithPrivateKey(intermediateKey);

		using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest leafRequest = new("CN=localhost", leafKey, HashAlgorithmName.SHA256);
		leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
		leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
		leafRequest.CertificateExtensions.Add
		(
			new X509EnhancedKeyUsageExtension
			(
				new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
				critical: true
			)
		);
		SubjectAlternativeNameBuilder san = new();
		san.AddDnsName("localhost");
		leafRequest.CertificateExtensions.Add(san.Build());
		using X509Certificate2 leafPublic = leafRequest.Create(intermediateWithKey, notBefore, notAfter, CreateSerialNumber());

		return
		(
			X509CertificateLoader.LoadCertificate(rootWithKey.RawDataMemory.Span),
			X509CertificateLoader.LoadCertificate(intermediatePublic.RawDataMemory.Span),
			leafPublic.CopyWithPrivateKey(leafKey)
		);
	}

	/// <summary>用显式提供的 intermediate 和自定义信任锚构建链；调用方保留入参所有权，Build 产生的链元素在此释放。</summary>
	public static bool BuildChainWithExplicitIntermediate(X509Certificate2 trustedRoot, X509Certificate2 intermediate, X509Certificate2 cert)
	{
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.DisableCertificateDownloads = true;
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
		chain.ChainPolicy.ExtraStore.Add(intermediate);
		try
		{
			return chain.Build(cert);
		}
		finally
		{
			DisposeChainElements(chain);
		}
	}

	public static void DisposeChainElements(X509Chain chain)
	{
		foreach (X509ChainElement chainElement in chain.ChainElements)
		{
			chainElement.Certificate.Dispose();
		}
	}

	public static X509Certificate2 CreateEcdsaSelfSignedWithIpAddress(string ipAddress)
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest req = new("CN=ip.localhost", key, HashAlgorithmName.SHA256);
		SubjectAlternativeNameBuilder san = new();
		san.AddIpAddress(IPAddress.Parse(ipAddress));
		req.CertificateExtensions.Add(san.Build());
		return ExportAndReload(req);
	}

	public static X509Certificate2 CreateWithClientAuthEkuOnly()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest req = new("CN=localhost", key, HashAlgorithmName.SHA256);
		req.CertificateExtensions.Add
		(
			new X509EnhancedKeyUsageExtension
			(
				new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },
				critical: true
			)
		);
		return ExportAndReload(req);
	}

	public static X509Certificate2 CreateWithServerAuthEkuOnly()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest req = new("CN=localhost", key, HashAlgorithmName.SHA256);
		req.CertificateExtensions.Add
		(
			new X509EnhancedKeyUsageExtension
			(
				new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
				critical: true
			)
		);
		return ExportAndReload(req);
	}

	public static bool ValidateSelfSigned(X509Certificate2 trustedRoot, X509Certificate2? remoteCert, X509Chain? remoteChain, SslPolicyErrors errors)
	{
		if (remoteCert is null)
		{
			return false;
		}

		Assert.NotNull(remoteChain);

		if (remoteChain.ChainStatus.Length is not 1 || remoteChain.ChainStatus[0].Status is not X509ChainStatusFlags.UntrustedRoot)
		{
			Assert.Fail("Expected single UntrustedRoot status");
		}

		if (remoteChain.Build(remoteCert))
		{
			Assert.Fail("Chain should not build");
		}

		if (remoteCert.Verify())
		{
			Assert.Fail("Certificate should not verify");
		}

		if (!errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
		{
			Assert.Fail("Expected RemoteCertificateChainErrors");
		}

		if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) is not SslPolicyErrors.None)
		{
			Assert.Fail("Unexpected additional errors");
		}

		using X509Chain chain = new();
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
		chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
		return chain.Build(remoteCert);
	}

	public static bool ValidateSelfSignedAndMatchHostname(
		X509Certificate2 trustedRoot,
		string expectedHost,
		X509Certificate2? remoteCert,
		X509Chain? remoteChain,
		SslPolicyErrors errors)
	{
		return ValidateSelfSigned(trustedRoot, remoteCert, remoteChain, errors)
				&& remoteCert is not null
				&& remoteCert.MatchesHostname(expectedHost);
	}

	private static CertificateRequest CreateCaRequest(string subjectName, ECDsa key, bool hasPathLengthConstraint)
	{
		CertificateRequest request = new(subjectName, key, HashAlgorithmName.SHA256);
		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, hasPathLengthConstraint, 0, true));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
		return request;
	}

	private static byte[] CreateSerialNumber()
	{
		byte[] serial = RandomNumberGenerator.GetBytes(16);
		serial[0] = (byte)((serial[0] & 0x7F) | 1);
		return serial;
	}
}
