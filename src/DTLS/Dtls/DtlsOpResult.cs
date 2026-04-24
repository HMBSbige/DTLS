namespace DTLS.Dtls;

public readonly record struct DtlsOpResult
{
	public int BytesWritten { get; init; }
	public int BytesRead { get; init; }
	public long TimeoutMs { get; init; }
	public bool IsHandshaking { get; init; }
	public bool IsLocalClosed { get; init; }
	public bool IsPeerClosed { get; init; }
}
