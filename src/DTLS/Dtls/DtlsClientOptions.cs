using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

public sealed record DtlsClientOptions
{
	public required string ServerName { get; init; }

	public X509Certificate2? ClientCertificate { get; init; }

	public Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? RemoteCertificateValidation { get; init; }

	public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

	public SslProtocols Version { get; init; }
}
