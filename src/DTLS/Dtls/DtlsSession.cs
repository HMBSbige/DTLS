using DTLS.Common;
using DTLS.Interop;
using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

/// <summary>DTLS protocol processing without I/O.</summary>
public sealed class DtlsSession : IDisposable
{
	private static readonly Oid ServerAuthOid = new("1.3.6.1.5.5.7.3.1");
	private static readonly Oid ClientAuthOid = new("1.3.6.1.5.5.7.3.2");
	private static readonly IdnMapping Idn = new();

	private readonly Lock _sync = new();
	private readonly SafeDtlsSessionHandle _handle;
	private Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? _validationCallback;
	private readonly bool _isServer;
	private readonly bool _remoteCertRequired;
	private readonly string? _targetHost;
	private DtlsOpResult _state;
	private DtlsVersion? _protocol;
	private X509Certificate2? _remoteCertificate;
	private bool _authenticating;

	public bool IsHandshaking => State.IsHandshaking;

	/// <summary>Delay until the next protocol timeout; <see langword="null"/> disables the timer.</summary>
	public TimeSpan? Timeout => State.Timeout;

	public bool IsLocalClosed => State.IsLocalClosed;

	public bool IsPeerClosed => State.IsPeerClosed;

	/// <summary>Negotiated protocol; <see langword="null"/> until peer authentication succeeds.</summary>
	public DtlsVersion? Protocol
	{
		get
		{
			lock (_sync)
			{
				return _protocol;
			}
		}
	}

	private DtlsOpResult State
	{
		get
		{
			lock (_sync)
			{
				return _state;
			}
		}
	}

	private DtlsSession(SafeDtlsSessionHandle handle, DtlsOptions options, bool isServer, bool remoteCertRequired, string? targetHost, DtlsOpResult result)
	{
		_handle = handle;
		_validationCallback = options.RemoteCertificateValidation;
		_isServer = isServer;
		_remoteCertRequired = remoteCertRequired;
		_targetHost = targetHost;
		_state = result;
	}

	public static (DtlsSession Session, DtlsOpResult Result) CreateClient(DtlsClientOptions options, Span<byte> output)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentException.ThrowIfNullOrWhiteSpace(options.ServerName);
		string targetHost = NormalizeHostName(options.ServerName);
		(SafeDtlsSessionHandle handle, DtlsOpResult result) = NativeSessionApi.Create(options.ClientCertificate, true, options.MinVersion, options.MaxVersion, false, output);
		return (new DtlsSession(handle, options, false, true, targetHost, result), result);
	}

	public static (DtlsSession Session, DtlsOpResult Result) CreateServer(DtlsServerOptions options, Span<byte> output)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(options.Certificate);
		bool requestCertificate = options.RequireClientCertificate || options.RemoteCertificateValidation is not null;
		(SafeDtlsSessionHandle handle, DtlsOpResult result) = NativeSessionApi.Create(options.Certificate, false, options.MinVersion, options.MaxVersion, requestCertificate, output);
		return (new DtlsSession(handle, options, true, options.RequireClientCertificate, null, result), result);
	}

	public DtlsOpResult Feed(ReadOnlySpan<byte> datagram, Span<byte> output)
	{
		lock (_sync)
		{
			ThrowIfUnavailable();
			return Complete(NativeSessionApi.Feed(_handle, datagram, output));
		}
	}

	public DtlsOpResult HandleTimeout(Span<byte> output)
	{
		lock (_sync)
		{
			ThrowIfUnavailable();
			return Complete(NativeSessionApi.HandleTimeout(_handle, output));
		}
	}

	public DtlsOpResult Send(ReadOnlySpan<byte> plaintext, Span<byte> output)
	{
		lock (_sync)
		{
			ThrowIfUnavailable();
			return Complete(NativeSessionApi.Send(_handle, plaintext, output));
		}
	}

	public DtlsOpResult Close(Span<byte> output)
	{
		lock (_sync)
		{
			ThrowIfUnavailable();
			return Complete(NativeSessionApi.Close(_handle, output));
		}
	}

	public bool TryReceive(Span<byte> buffer, out int bytesRead)
	{
		lock (_sync)
		{
			ThrowIfUnavailable();
			DtlsCallResultNative result = NativeSessionApi.Receive(_handle, buffer);
			bytesRead = Complete(in result).BytesRead;
			return result.Code is DtlsResult.Ok;
		}
	}

	/// <summary>Returns a caller-owned certificate copy, or <see langword="null"/> before authentication or if absent.</summary>
	public X509Certificate2? GetRemoteCertificate()
	{
		lock (_sync)
		{
			ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
			return _protocol is not null && _remoteCertificate is { } certificate ? new X509Certificate2(certificate) : null;
		}
	}

	public void Dispose()
	{
		lock (_sync)
		{
			_validationCallback = null;
			_remoteCertificate?.Dispose();
			_remoteCertificate = null;
			_handle.Dispose();
		}
	}

	internal void ThrowIfUnavailable()
	{
		lock (_sync)
		{
			ObjectDisposedException.ThrowIf(_handle.IsClosed, this);

			if (_authenticating)
			{
				throw new InvalidOperationException("Cannot drive the DTLS session from its certificate validation callback.");
			}
		}
	}

	private DtlsOpResult Complete(in DtlsCallResultNative result)
	{
		_state = NativeSessionApi.ToOpResult(in result);
		NativeHelper.ThrowIfError(result.Code);

		if (_state is { IsHandshaking: false, IsLocalClosed: false } && _protocol is null)
		{
			AuthenticatePeer();
		}

		return _state;
	}

	private void AuthenticatePeer()
	{
		_authenticating = true;

		try
		{
			(DtlsVersion protocol, X509Certificate2? certificate) = NativeSessionApi.GetConnectionInfo(_handle);
			_remoteCertificate = certificate;
			using X509Chain? chain = certificate is null ? null : new();
			X509ChainElementCollection? originalElements = null;

			try
			{
				SslPolicyErrors errors = SslPolicyErrors.RemoteCertificateNotAvailable;

				if (certificate is not null && chain is not null)
				{
					chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
					chain.ChainPolicy.ApplicationPolicy.Add(_isServer ? ClientAuthOid : ServerAuthOid);
					errors = VerifyCertificate(chain, certificate, _targetHost);
					originalElements = chain.ChainElements;
				}

				if (_validationCallback is { } validate)
				{
					if (!validate(certificate, chain, errors))
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

				ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
				_protocol = protocol;
			}
			finally
			{
				DisposeChainElements(originalElements);

				if (chain is not null && !ReferenceEquals(originalElements, chain.ChainElements))
				{
					DisposeChainElements(chain.ChainElements);
				}
			}
		}
		catch
		{
			Dispose();
			throw;
		}
		finally
		{
			_validationCallback = null;
			_authenticating = false;
		}
	}

	private static void DisposeChainElements(X509ChainElementCollection? elements)
	{
		if (elements is null)
		{
			return;
		}

		foreach (X509ChainElement element in elements)
		{
			element.Certificate.Dispose();
		}
	}

	private static SslPolicyErrors VerifyCertificate(X509Chain chain, X509Certificate2 certificate, string? targetHost)
	{
		SslPolicyErrors errors = chain.Build(certificate) ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors;

		if (!string.IsNullOrEmpty(targetHost) && !certificate.MatchesHostname(targetHost))
		{
			errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
		}

		return errors;
	}

	private static string NormalizeHostName(string targetHost)
	{
		targetHost = targetHost.TrimEnd('.');
		ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);
		return Uri.CheckHostName(targetHost) is UriHostNameType.IPv4 or UriHostNameType.IPv6 ? targetHost : Idn.GetAscii(targetHost);
	}
}
