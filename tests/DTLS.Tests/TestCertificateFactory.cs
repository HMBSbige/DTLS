using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

internal static class TestCertificateFactory
{
	public static X509Certificate2 CreateEcdsaSelfSigned()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest req = new("CN=localhost", key, HashAlgorithmName.SHA256);
		SubjectAlternativeNameBuilder san = new();
		san.AddDnsName("localhost");
		req.CertificateExtensions.Add(san.Build());
		return ExportAndReload(req);
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
		Assert.Single(remoteChain.ChainStatus, s => s.Status is X509ChainStatusFlags.UntrustedRoot);
		Assert.False(remoteChain.Build(remoteCert));
		Assert.False(remoteCert.Verify());

		Assert.True(errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
		Assert.True((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) is SslPolicyErrors.None);

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

	private static X509Certificate2 ExportAndReload(CertificateRequest request)
	{
		DateTimeOffset now = DateTimeOffset.UtcNow;
		using X509Certificate2 tmp = request.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
		return X509CertificateLoader.LoadPkcs12
		(
			tmp.Export(X509ContentType.Pfx),
			default,
			X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet
		);
	}
}
