using System.Runtime.InteropServices;

namespace DTLS.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct DtlsOpStatusNative
{
	public long TimeoutMs;
	public byte IsHandshaking;
}
