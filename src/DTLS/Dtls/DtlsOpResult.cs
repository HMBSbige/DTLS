namespace DTLS.Dtls;

public readonly record struct DtlsOpResult
{
	public int BytesWritten { get; init; }
	public int BytesRead { get; init; }
	/// <summary>Delay until the next protocol timeout; <see langword="null"/> disables the timer.</summary>
	public TimeSpan? Timeout { get; init; }
	public bool IsHandshaking { get; init; }
	public bool IsLocalClosed { get; init; }
	public bool IsPeerClosed { get; init; }
}
