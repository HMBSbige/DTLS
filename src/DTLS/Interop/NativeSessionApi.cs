using DTLS.Dtls;
using System.Runtime.CompilerServices;

namespace DTLS.Interop;

internal static class NativeSessionApi
{
	public static unsafe (SafeDtlsSessionHandle Handle, DtlsOpResult Result) Create(
		ReadOnlySpan<byte> certDer, ReadOnlySpan<byte> keyDer,
		bool isClient, uint version, bool requireClientCertificate,
		Span<byte> output)
	{
		fixed (byte* certPtr = certDer)
		fixed (byte* keyPtr = keyDer)
		{
			DtlsSessionNewConfigNative config = new()
			{
				CertDer = (nint)certPtr,
				CertLen = (nuint)certDer.Length,
				KeyDer = (nint)keyPtr,
				KeyLen = (nuint)keyDer.Length,
				IsClient = Convert.ToByte(isClient),
				Version = version,
				RequireClientCertificate = Convert.ToByte(requireClientCertificate),
			};
			DtlsCallResultNative r = NativeMethods.SessionNew(in config, out nint ptr, output, (nuint)output.Length);
			NativeHelper.ThrowIfError(r.Code);
			return (new SafeDtlsSessionHandle(ptr), ToOpResult(in r));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static DtlsCallResultNative Feed(SafeDtlsSessionHandle handle, ReadOnlySpan<byte> data, Span<byte> output)
	{
		return NativeMethods.SessionFeed(handle, data, (nuint)data.Length, output, (nuint)output.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static DtlsCallResultNative HandleTimeout(SafeDtlsSessionHandle handle, Span<byte> output)
	{
		return NativeMethods.SessionHandleTimeout(handle, output, (nuint)output.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static DtlsCallResultNative Send(SafeDtlsSessionHandle handle, ReadOnlySpan<byte> data, Span<byte> output)
	{
		return NativeMethods.SessionSend(handle, data, (nuint)data.Length, output, (nuint)output.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static DtlsCallResultNative Receive(SafeDtlsSessionHandle handle, Span<byte> buffer)
	{
		return NativeMethods.SessionReceive(handle, buffer, (nuint)buffer.Length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static DtlsCallResultNative Snapshot(SafeDtlsSessionHandle handle, out DtlsConnectionSnapshotNative snapshot)
	{
		return NativeMethods.SessionConnectionSnapshot(handle, out snapshot);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static DtlsOpResult ToOpResult(in DtlsCallResultNative r)
	{
		return new DtlsOpResult
		{
			BytesWritten = (int)r.BytesWritten,
			BytesRead = (int)r.BytesRead,
			TimeoutMs = r.Status.TimeoutMs,
			IsHandshaking = r.Status.IsHandshaking is not 0
		};
	}
}
