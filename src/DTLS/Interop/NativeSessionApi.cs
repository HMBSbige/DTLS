using DTLS.Common;
using DTLS.Dtls;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Interop;

internal static class NativeSessionApi
{
	public static (SafeDtlsSessionHandle Handle, DtlsOpResult Result) Create(X509Certificate2? certificate, bool isClient, DtlsVersion? minVersion, DtlsVersion? maxVersion, bool requireClientCertificate, Span<byte> output)
	{
		if (minVersion is not (null or DtlsVersion.Dtls12 or DtlsVersion.Dtls13))
		{
			throw new ArgumentOutOfRangeException(nameof(minVersion), minVersion, "Unsupported DTLS version.");
		}
		if (maxVersion is not (null or DtlsVersion.Dtls12 or DtlsVersion.Dtls13))
		{
			throw new ArgumentOutOfRangeException(nameof(maxVersion), maxVersion, "Unsupported DTLS version.");
		}
		if (minVersion > maxVersion)
		{
			throw new ArgumentException("The maximum DTLS version must not be lower than the minimum version.", nameof(maxVersion));
		}

		if (certificate is null)
		{
			return CreateCore([], [], isClient, minVersion, maxVersion, requireClientCertificate, output);
		}

		using ECDsa key = certificate.GetECDsaPrivateKey()
						?? throw new CryptographicException("The certificate must contain an exportable ECDSA private key.");
		byte[] keyDer = key.ExportPkcs8PrivateKey();

		try
		{
			return CreateCore(certificate.RawDataMemory.Span, keyDer, isClient, minVersion, maxVersion, requireClientCertificate, output);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(keyDer);
		}
	}

	private static unsafe (SafeDtlsSessionHandle Handle, DtlsOpResult Result) CreateCore
	(
		ReadOnlySpan<byte> certDer, ReadOnlySpan<byte> keyDer,
		bool isClient, DtlsVersion? minVersion, DtlsVersion? maxVersion, bool requireClientCertificate,
		Span<byte> output
	)
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
				MinVersion = (uint)minVersion.GetValueOrDefault(),
				MaxVersion = (uint)maxVersion.GetValueOrDefault(),
				RequireClientCertificate = Convert.ToByte(requireClientCertificate),
			};
			DtlsCallResultNative result = NativeMethods.SessionNew(in config, out SafeDtlsSessionHandle handle, output, (nuint)output.Length);

			try
			{
				NativeHelper.ThrowIfError(result.Code);
				return (handle, ToOpResult(in result));
			}
			catch
			{
				handle.Dispose();
				throw;
			}
		}
	}

	public static DtlsCallResultNative Feed(SafeDtlsSessionHandle handle, ReadOnlySpan<byte> data, Span<byte> output)
	{
		return NativeMethods.SessionFeed(handle, data, (nuint)data.Length, output, (nuint)output.Length);
	}

	public static DtlsCallResultNative HandleTimeout(SafeDtlsSessionHandle handle, Span<byte> output)
	{
		return NativeMethods.SessionHandleTimeout(handle, output, (nuint)output.Length);
	}

	public static DtlsCallResultNative Send(SafeDtlsSessionHandle handle, ReadOnlySpan<byte> data, Span<byte> output)
	{
		return NativeMethods.SessionSend(handle, data, (nuint)data.Length, output, (nuint)output.Length);
	}

	public static DtlsCallResultNative Receive(SafeDtlsSessionHandle handle, Span<byte> buffer)
	{
		return NativeMethods.SessionReceive(handle, buffer, (nuint)buffer.Length);
	}

	public static (DtlsVersion Protocol, X509Certificate2? Certificate) GetConnectionInfo(SafeDtlsSessionHandle handle)
	{
		DtlsCallResultNative snapshotResult = NativeMethods.SessionConnectionSnapshot(handle, out DtlsConnectionSnapshotNative snapshot);
		NativeHelper.ThrowIfError(snapshotResult.Code);
		DtlsVersion protocol = (DtlsVersion)snapshot.Protocol;
		if (protocol is not (DtlsVersion.Dtls12 or DtlsVersion.Dtls13))
		{
			throw new DtlsException(DtlsResult.DtlsError, $"Unsupported negotiated DTLS protocol: 0x{snapshot.Protocol:X4}.");
		}

		DtlsCallResultNative probe = NativeMethods.SessionCopyPeerCert(handle, [], 0);
		NativeHelper.ThrowIfError(probe.Code);

		if (probe.BytesRead is 0)
		{
			return (protocol, null);
		}

		byte[] certificateDer = new byte[checked((int)probe.BytesRead)];
		DtlsCallResultNative copy = NativeMethods.SessionCopyPeerCert(handle, certificateDer, (nuint)certificateDer.Length);
		NativeHelper.ThrowIfError(copy.Code);
		return (protocol, X509CertificateLoader.LoadCertificate(certificateDer.AsSpan(0, checked((int)copy.BytesRead))));
	}

	public static DtlsCallResultNative Close(SafeDtlsSessionHandle handle, Span<byte> output)
	{
		return NativeMethods.SessionClose(handle, output, (nuint)output.Length);
	}

	public static DtlsOpResult ToOpResult(in DtlsCallResultNative result)
	{
		return new DtlsOpResult
		{
			BytesWritten = checked((int)result.BytesWritten),
			BytesRead = checked((int)result.BytesRead),
			Timeout = result.Status.TimeoutMs < 0 ? null : TimeSpan.FromMilliseconds(result.Status.TimeoutMs),
			IsHandshaking = result.Status.IsHandshaking is not 0,
			IsLocalClosed = result.Status.IsLocalClosed is not 0,
			IsPeerClosed = result.Status.IsPeerClosed is not 0
		};
	}
}
