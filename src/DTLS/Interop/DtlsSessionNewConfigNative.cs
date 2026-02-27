using System.Runtime.InteropServices;

namespace DTLS.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct DtlsSessionNewConfigNative
{
	public nint CertDer;
	public nuint CertLen;
	public nint KeyDer;
	public nuint KeyLen;
	public byte IsClient;
	public uint Version;
	public byte RequireClientCertificate;
}
