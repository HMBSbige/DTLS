using System.Runtime.InteropServices;

namespace DTLS.Interop;

internal sealed class SafeDtlsSessionHandle(nint handle) : SafeHandle(handle, true)
{
	public override bool IsInvalid => handle == nint.Zero;

	protected override bool ReleaseHandle()
	{
		NativeMethods.SessionFree(handle);
		return true;
	}
}
