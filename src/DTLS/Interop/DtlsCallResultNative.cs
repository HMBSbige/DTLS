using System.Runtime.InteropServices;

namespace DTLS.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct DtlsCallResultNative
{
	public DtlsResult Code;
	public nuint BytesWritten;
	public nuint BytesRead;
	public DtlsOpStatusNative Status;
}
