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

	public SslProtocols Protocol { get; private set; }

	public TlsCipherSuite CipherSuite { get; private set; }

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

	public DtlsOpResult TryReceive(Span<byte> buffer)
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
		DtlsCallResultNative r = NativeSessionApi.Receive(_handle, buffer);

		if (r.Code is DtlsResult.WouldBlock || r is { Code: DtlsResult.Ok, BytesRead: 0 })
		{
			return NativeSessionApi.ToOpResult(in r);
		}

		NativeHelper.ThrowIfError(r.Code);
		return Complete(r);
	}

	public void VerifyPeer()
	{
		ObjectDisposedException.ThrowIf(_handle.IsClosed, this);

		X509Chain? chain = null;
		SslPolicyErrors errors = SslPolicyErrors.None;

		try
		{
			(X509Certificate2? peerCert, chain) = LoadPeerCertificates();

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
				chain ??= new X509Chain();
				chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

				chain.ChainPolicy.ApplicationPolicy.Add(_isServer ? ClientAuthOid : ServerAuthOid);

				errors |= VerifyCertificate(chain, peerCert, _targetHost);
			}

			SetRemoteCertificate(peerCert);

			if (_validationCallback is not null)
			{
				// Callback may capture cert/chain references. We intentionally do not dispose peerCert/chain
				// internals in this method when a callback is used; ownership is effectively externalized.
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
					foreach (X509Certificate2 c in chain.ChainPolicy.ExtraStore)
					{
						c.Dispose();
					}

					foreach (X509ChainElement chainElement in chain.ChainElements)
					{
						chainElement.Certificate.Dispose();
					}
				}
				// Dispose the chain object itself in all cases; with callback mode we keep certificate
				// objects alive to avoid invalidating references that user code may retain.

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
	/// 记得 dispose：叶子证书和临时中间证书 X509Chain.ChainPolicy.ExtraStore
	/// </summary>
	private unsafe (X509Certificate2? PeerCert, X509Chain? Chain) LoadPeerCertificates()
	{
		DtlsCallResultNative r = NativeSessionApi.Snapshot(_handle, out DtlsConnectionSnapshotNative snap);
		NativeHelper.ThrowIfError(r.Code);
		Protocol = snap.Protocol switch
		{
			0x0303 => SslProtocols.Tls12,
			0x0304 => SslProtocols.Tls13,
			_ => SslProtocols.None
		};
		CipherSuite = (TlsCipherSuite)snap.CipherSuite;

		if (snap.PeerCertLen is 0)
		{
			return (null, null);
		}

		X509Certificate2 peerCert = X509CertificateLoader.LoadCertificate(new ReadOnlySpan<byte>((void*)snap.PeerCertPtr, (int)snap.PeerCertLen));

		X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

		if (snap.PeerChainLen > 0)
		{
			foreach (ReadOnlySpan<byte> der in new FramedPacketEnumerator(new ReadOnlySpan<byte>((void*)snap.PeerChainPtr, (int)snap.PeerChainLen)))
			{
				chain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(der));
			}
		}

		return (peerCert, chain);
	}

	private DtlsOpResult Complete(in DtlsCallResultNative r)
	{
		NativeHelper.ThrowIfError(r.Code);
		DtlsOpResult result = NativeSessionApi.ToOpResult(in r);
		IsHandshaking = result.IsHandshaking;
		TimeoutMs = result.TimeoutMs;
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
