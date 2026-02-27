using DTLS.Interop;

namespace DTLS.Common;

/// <summary>
/// Thrown when certificate validation fails.
/// </summary>
public class CertificateException : DtlsException
{
	public CertificateException(string? message = null) : base(DtlsResult.CertificateError, message)
	{
	}

	public CertificateException(string? message, Exception? innerException) : base(DtlsResult.CertificateError, message, innerException)
	{
	}
}
