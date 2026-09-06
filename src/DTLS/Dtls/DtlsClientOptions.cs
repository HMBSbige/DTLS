using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

public sealed record DtlsClientOptions : DtlsOptions
{
	public required string ServerName { get; init; }

	public X509Certificate2? ClientCertificate { get; init; }
}
