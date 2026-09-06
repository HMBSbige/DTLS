using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

public sealed record DtlsServerOptions : DtlsOptions
{
	public required X509Certificate2 Certificate { get; init; }

	public bool RequireClientCertificate { get; init; }
}
