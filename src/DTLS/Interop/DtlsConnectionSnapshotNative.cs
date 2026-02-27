using System.Runtime.InteropServices;

namespace DTLS.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct DtlsConnectionSnapshotNative
{
	public ushort Protocol;
	public ushort CipherSuite;
	public nint PeerCertPtr;
	public nuint PeerCertLen;
	public nint PeerChainPtr;
	public nuint PeerChainLen;
}
