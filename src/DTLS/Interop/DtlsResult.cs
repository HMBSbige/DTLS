namespace DTLS.Interop;

/// <summary>
/// Mirrors the Rust-side DtlsResult enum.
/// Non-negative values are status codes; negative values are errors.
/// </summary>
public enum DtlsResult
{
	Ok = 0,
	WouldBlock = 1,
	CertificateError = -1,
	InvalidInput = -2,
	DtlsError = -3,
	BufferTooSmall = -4,
	Panic = -99
}
