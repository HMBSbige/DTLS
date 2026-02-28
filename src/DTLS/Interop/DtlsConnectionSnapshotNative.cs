using System.Runtime.InteropServices;

namespace DTLS.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct DtlsConnectionSnapshotNative
{
	public ushort Protocol;
}
