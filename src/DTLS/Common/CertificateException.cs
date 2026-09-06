using DTLS.Interop;

namespace DTLS.Common;

public class CertificateException(string? message = null, Exception? innerException = null) : DtlsException(DtlsResult.CertificateError, message, innerException);
