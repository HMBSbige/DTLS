using DTLS.Common;
using DTLS.Interop;
using System.Globalization;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

public sealed class DtlsSession : IDisposable
{
	private readonly SafeDtlsSessionHandle _handle;
	private readonly Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? _validationCallback;
	private readonly bool _isServer;
	private readonly bool _remoteCertRequired;
	private readonly string? _targetHost;
	private X509Certificate2? _remoteCertificate;
	private bool _remoteCertificateExposed;

	public bool IsHandshaking { get; private set; }

	public long TimeoutMs { get; private set; }

	public bool IsLocalClosed { get; private set; }

	public bool IsPeerClosed { get; private set; }

	public SslProtocols Protocol { get; private set; }

	/// <summary>
	/// 获取远程对等方的证书。
	/// </summary>
	/// <remarks>
	/// 生命周期：访问此属性会将证书所有权转移给调用方。
	/// 一旦访问，调用方负责在不再需要时 dispose 此证书对象。
	/// 如果从未访问此属性，<see cref="DtlsSession"/> 会在 dispose 时自动释放证书。
	/// </remarks>
	public X509Certificate2? RemoteCertificate
	{
		get
		{
			_remoteCertificateExposed = true;
			return _remoteCertificate;
		}
	}

	public void Dispose()
	{
		if (!_remoteCertificateExposed)
		{
			_remoteCertificate?.Dispose();
		}

		_remoteCertificate = null;
		_handle.Dispose();
	}

	private DtlsSession(SafeDtlsSessionHandle handle,
		bool isServer,
		bool remoteCertRequired,
		string? targetHost,
		Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? validationCallback,
		in DtlsOpResult result)
	{
		_handle = handle;
		_isServer = isServer;
		_remoteCertRequired = remoteCertRequired;
		_targetHost = targetHost;
		_validationCallback = validationCallback;
		IsHandshaking = result.IsHandshaking;
		TimeoutMs = result.TimeoutMs;
		IsLocalClosed = result.IsLocalClosed;
		IsPeerClosed = result.IsPeerClosed;
	}

	// ── Factory methods ──────────────────────────────────────

	public static (DtlsSession Session, DtlsOpResult Result) CreateClient(DtlsClientOptions options, Span<byte> output)
	{
		ValidateVersion(options.Version);

		ReadOnlySpan<byte> certDer = default;
		Span<byte> keyBuf = stackalloc byte[NativeHelper.MaxPkcs8KeySize];
		int keyLen = 0;

		if (options.ClientCertificate is { } cert)
		{
			certDer = NativeHelper.ExportCertAndKey(cert, keyBuf, out keyLen);
		}

		string? targetHost = NormalizeHostName(options.ServerName);
		(SafeDtlsSessionHandle handle, DtlsOpResult result) = NativeSessionApi.Create
		(
			certDer,
			keyBuf.Slice(0, keyLen),
			true,
			(uint)options.Version,
			false,
			output
		);
		return (new DtlsSession(handle, false, true, targetHost, options.RemoteCertificateValidation, in result), result);
	}

	public static (DtlsSession Session, DtlsOpResult Result) CreateServer(DtlsServerOptions options, Span<byte> output)
	{
		ValidateVersion(options.Version);

		Span<byte> keyBuf = stackalloc byte[NativeHelper.MaxPkcs8KeySize];
		ReadOnlySpan<byte> certDer = NativeHelper.ExportCertAndKey(options.Certificate, keyBuf, out int keyLen);
		(SafeDtlsSessionHandle handle, DtlsOpResult result) = NativeSessionApi.Create
		(
			certDer,
			keyBuf.Slice(0, keyLen),
			false,
			(uint)options.Version,
			options.RequireClientCertificate || options.RemoteCertificateValidation is not null,
			output
		);
		return (new DtlsSession(handle, true, options.RequireClientCertificate, null, options.RemoteCertificateValidation, in result), result);
	}

	// ── Sans-I/O protocol operations ────────────────────────

	public DtlsOpResult Feed(ReadOnlySpan<byte> data, Span<byte> output)
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
		return Complete(NativeSessionApi.Feed(_handle, data, output));
	}

	public DtlsOpResult HandleTimeout(Span<byte> output)
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
		return Complete(NativeSessionApi.HandleTimeout(_handle, output));
	}

	public DtlsOpResult Send(ReadOnlySpan<byte> plaintext, Span<byte> output)
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
		return Complete(NativeSessionApi.Send(_handle, plaintext, output));
	}

	/// <summary>
	/// 发起优雅关闭：排队一条 <c>close_notify</c> 告警并刷新输出。
	/// </summary>
	public DtlsOpResult Close(Span<byte> output)
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
		return Complete(NativeSessionApi.Close(_handle, output));
	}

	public DtlsOpResult TryReceive(Span<byte> buffer)
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
		return Complete(NativeSessionApi.Receive(_handle, buffer));
	}

	public void VerifyPeer()
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);

		X509Chain? chain = null;
		SslPolicyErrors errors = SslPolicyErrors.None;

		try
		{
			X509Certificate2? peerCert = LoadPeerCertificate();

			if (_remoteCertificate is not null && peerCert is not null && peerCert.RawDataMemory.Span.SequenceEqual(_remoteCertificate.RawDataMemory.Span))
			{
				peerCert.Dispose();
				return;
			}

			if (peerCert is null)
			{
				errors |= SslPolicyErrors.RemoteCertificateNotAvailable;
			}
			else
			{
				chain = new X509Chain();
				chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

				chain.ChainPolicy.ApplicationPolicy.Add(_isServer ? ClientAuthOid : ServerAuthOid);

				errors |= VerifyCertificate(chain, peerCert, _targetHost);
			}

			SetRemoteCertificate(peerCert);

			if (_validationCallback is not null)
			{
				if (!_validationCallback(peerCert, chain, errors))
				{
					throw new CertificateException("Remote certificate validation failed by user callback.");
				}
			}
			else
			{
				if (!_remoteCertRequired)
				{
					errors &= ~SslPolicyErrors.RemoteCertificateNotAvailable;
				}

				if (errors is not SslPolicyErrors.None)
				{
					throw new CertificateException($"Remote certificate validation failed: {errors}");
				}
			}
		}
		finally
		{
			if (chain is not null)
			{
				if (_validationCallback is null)
				{
					foreach (X509ChainElement chainElement in chain.ChainElements)
					{
						chainElement.Certificate.Dispose();
					}
				}
				// X509Chain 对象本身在所有情况下都会被释放；
				// 当启用回调时，仅保留链内证书对象存活，以避免使用户代码可能保留的证书引用失效

				chain.Dispose();
			}
		}
	}

	// ── Private ─────────────────────────────────────────────

	private static readonly Oid ServerAuthOid = new("1.3.6.1.5.5.7.3.1");
	private static readonly Oid ClientAuthOid = new("1.3.6.1.5.5.7.3.2");

	private static readonly IdnMapping Idn = new();

	private static void ValidateVersion(SslProtocols version)
	{
		if (version is SslProtocols.None or SslProtocols.Tls12 or SslProtocols.Tls13)
		{
			return;
		}

		throw new ArgumentOutOfRangeException(nameof(version), version, "Version must be None, Tls12, or Tls13.");
	}

	internal static SslPolicyErrors VerifyCertificate(X509Chain chain, X509Certificate2 certificate, string? targetHost)
	{
		SslPolicyErrors errors = SslPolicyErrors.None;

		if (!chain.Build(certificate))
		{
			errors |= SslPolicyErrors.RemoteCertificateChainErrors;
		}

		if (!string.IsNullOrEmpty(targetHost) && !certificate.MatchesHostname(targetHost))
		{
			errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
		}

		return errors;
	}

	private static string? NormalizeHostName(string? targetHost)
	{
		if (string.IsNullOrEmpty(targetHost))
		{
			return null;
		}

		targetHost = targetHost.TrimEnd('.');

		try
		{
			return Idn.GetAscii(targetHost);
		}
		catch (ArgumentException) when (Uri.CheckHostName(targetHost) is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6)
		{
		}

		return targetHost;
	}

	/// <summary>
	/// 从当前会话快照加载对端叶子证书，返回对象由调用方负责释放。
	/// </summary>
	private X509Certificate2? LoadPeerCertificate()
	{
		DtlsCallResultNative r = NativeSessionApi.Snapshot(_handle, out DtlsConnectionSnapshotNative snap);
		NativeHelper.ThrowIfError(r.Code);
		Protocol = (SslProtocols)snap.Protocol;

		// Probe peer cert length
		DtlsCallResultNative certProbe = NativeSessionApi.CopyPeerCert(_handle, Span<byte>.Empty);
		NativeHelper.ThrowIfError(certProbe.Code);
		if (certProbe.BytesRead is 0)
		{
			return null;
		}

		// Copy peer cert
		byte[] certBuf = new byte[(int)certProbe.BytesRead];
		DtlsCallResultNative certCopy = NativeSessionApi.CopyPeerCert(_handle, certBuf);
		NativeHelper.ThrowIfError(certCopy.Code);
		return X509CertificateLoader.LoadCertificate(certBuf.AsSpan(0, (int)certCopy.BytesRead));
	}

	private DtlsOpResult Complete(in DtlsCallResultNative r)
	{
		DtlsOpResult result = NativeSessionApi.ToOpResult(in r);
		IsHandshaking = result.IsHandshaking;
		TimeoutMs = result.TimeoutMs;
		IsLocalClosed = result.IsLocalClosed;
		IsPeerClosed = result.IsPeerClosed;
		NativeHelper.ThrowIfError(r.Code);
		return result;
	}

	private void SetRemoteCertificate(X509Certificate2? certificate)
	{
		X509Certificate2? previous = _remoteCertificate;
		bool previousExposed = _remoteCertificateExposed;
		_remoteCertificate = certificate;
		_remoteCertificateExposed = false;

		if (previous is not null && !previousExposed)
		{
			previous.Dispose();
		}
	}
}
