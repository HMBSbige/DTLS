using DTLS.Common;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DTLS.Interop;

internal static class NativeHelper
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ThrowIfError(DtlsResult result)
	{
		if ((int)result >= 0)
		{
			return;
		}

		Span<byte> buf = stackalloc byte[1024];
		int msgLen = NativeMethods.LastErrorMessage(buf, buf.Length);

		string message = msgLen > 0
			? Encoding.UTF8.GetString(buf.Slice(0, msgLen))
			: result.ToString();

		throw result switch
		{
			DtlsResult.CertificateError => new CertificateException(message),
			_ => new DtlsException(result, message)
		};
	}

	public const int MaxPkcs8KeySize = 256;

	public static ReadOnlySpan<byte> ExportCertAndKey(X509Certificate2 certificate, scoped Span<byte> keyBuf, out int keyBytesWritten)
	{
		using ECDsa? ecdsa = certificate.GetECDsaPrivateKey();

		if (ecdsa is not null && ecdsa.TryExportPkcs8PrivateKey(keyBuf, out keyBytesWritten))
		{
			return certificate.RawDataMemory.Span;
		}

		throw new CryptographicException("Unable to export private key from the certificate.");
	}
}
