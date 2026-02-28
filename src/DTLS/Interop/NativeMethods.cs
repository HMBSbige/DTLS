using System.Runtime.InteropServices;

namespace DTLS.Interop;

internal static partial class NativeMethods
{
	private const string LibName = "dtls_native";

	[LibraryImport(LibName, EntryPoint = "dtls_last_error_message")]
	public static partial int LastErrorMessage(Span<byte> buf, int bufLen);

	[LibraryImport(LibName, EntryPoint = "dtls_session_new")]
	public static partial DtlsCallResultNative SessionNew(
		in DtlsSessionNewConfigNative config,
		out nint session,
		Span<byte> outPkts, nuint outPktsCap);

	[LibraryImport(LibName, EntryPoint = "dtls_session_feed")]
	public static partial DtlsCallResultNative SessionFeed(
		SafeDtlsSessionHandle session,
		ReadOnlySpan<byte> input, nuint inputLen,
		Span<byte> outPkts, nuint outPktsCap);

	[LibraryImport(LibName, EntryPoint = "dtls_session_handle_timeout")]
	public static partial DtlsCallResultNative SessionHandleTimeout(
		SafeDtlsSessionHandle session,
		Span<byte> outPkts, nuint outPktsCap);

	[LibraryImport(LibName, EntryPoint = "dtls_session_send")]
	public static partial DtlsCallResultNative SessionSend(
		SafeDtlsSessionHandle session,
		ReadOnlySpan<byte> data, nuint dataLen,
		Span<byte> outPkts, nuint outPktsCap);

	[LibraryImport(LibName, EntryPoint = "dtls_session_recv")]
	public static partial DtlsCallResultNative SessionReceive(
		SafeDtlsSessionHandle session,
		Span<byte> buf, nuint bufLen);

	[LibraryImport(LibName, EntryPoint = "dtls_session_connection_snapshot")]
	public static partial DtlsCallResultNative SessionConnectionSnapshot(
		SafeDtlsSessionHandle session,
		out DtlsConnectionSnapshotNative snapshot);

	[LibraryImport(LibName, EntryPoint = "dtls_session_copy_peer_cert")]
	public static partial DtlsCallResultNative SessionCopyPeerCert(
		SafeDtlsSessionHandle session,
		Span<byte> buf, nuint bufLen);

	[LibraryImport(LibName, EntryPoint = "dtls_session_copy_peer_chain")]
	public static partial DtlsCallResultNative SessionCopyPeerChain(
		SafeDtlsSessionHandle session,
		Span<byte> buf, nuint bufLen);

	[LibraryImport(LibName, EntryPoint = "dtls_session_free")]
	public static partial void SessionFree(nint session);
}
