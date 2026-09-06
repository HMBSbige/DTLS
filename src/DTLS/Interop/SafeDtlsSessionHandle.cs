using System.Runtime.InteropServices;

namespace DTLS.Interop;

internal sealed class SafeDtlsSessionHandle() : SafeHandle(nint.Zero, true)
{
	public override bool IsInvalid => handle == nint.Zero;

	protected override bool ReleaseHandle()
	{
		NativeMethods.SessionFree(handle);
		return true;
	}
}
