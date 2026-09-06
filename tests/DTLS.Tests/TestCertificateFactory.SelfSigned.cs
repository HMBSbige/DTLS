using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

// ReSharper disable once PartialTypeWithSinglePart
internal static partial class TestCertificateFactory
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

	private static X509Certificate2 ExportAndReload(CertificateRequest request)
	{
		DateTimeOffset now = DateTimeOffset.UtcNow;
		using X509Certificate2 tmp = request.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
		return X509CertificateLoader.LoadPkcs12(tmp.Export(X509ContentType.Pfx), default, X509KeyStorageFlags.Exportable);
	}
}
