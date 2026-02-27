using DTLS.Interop;

namespace DTLS.Common;

/// <summary>
/// Thrown when a DTLS handshake or retransmission times out.
/// </summary>
public class DtlsTimeoutException : DtlsException
{
	public DtlsTimeoutException(string? message = null) : base(DtlsResult.DtlsError, message)
	{
	}

	public DtlsTimeoutException(string? message, Exception? innerException) : base(DtlsResult.DtlsError, message, innerException)
	{
	}
}
