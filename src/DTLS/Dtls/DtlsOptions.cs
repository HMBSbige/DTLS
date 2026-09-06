using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

public abstract record DtlsOptions
{
	/// <summary>Defaults to system trust; clients also verify the server name.</summary>
	/// <remarks>
	/// The library disposes the callback certificate and chain.
	/// Dispose certificates you add to the chain policy and those from discarded intermediate builds.
	/// </remarks>
	public Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? RemoteCertificateValidation { get; init; }

	public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

	public DtlsVersion? MinVersion { get; init; }

	public DtlsVersion? MaxVersion { get; init; }
}
