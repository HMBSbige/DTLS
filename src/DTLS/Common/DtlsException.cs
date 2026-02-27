using DTLS.Interop;

namespace DTLS.Common;

/// <summary>
/// Base exception for all DTLS transport errors.
/// </summary>
public class DtlsException : Exception
{
	public DtlsResult ErrorCode { get; }

	public DtlsException(DtlsResult errorCode, string? message = null) : base(message ?? $"DTLS error: {errorCode}")
	{
		ErrorCode = errorCode;
	}

	public DtlsException(DtlsResult errorCode, string? message, Exception? innerException) : base(message ?? $"DTLS error: {errorCode}", innerException)
	{
		ErrorCode = errorCode;
	}
}
