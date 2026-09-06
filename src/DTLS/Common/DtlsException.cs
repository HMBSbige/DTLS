using DTLS.Interop;

namespace DTLS.Common;

public class DtlsException(DtlsResult errorCode, string? message = null, Exception? innerException = null) : Exception(message ?? $"DTLS error: {errorCode}", innerException)
{
	public DtlsResult ErrorCode { get; } = errorCode;
}
