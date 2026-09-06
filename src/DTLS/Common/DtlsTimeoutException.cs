using DTLS.Interop;

namespace DTLS.Common;

public class DtlsTimeoutException(string? message = null, Exception? innerException = null) : DtlsException(DtlsResult.DtlsError, message, innerException);
