using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Dtls;

public sealed record DtlsClientOptions
{
	public required string ServerName { get; init; }

	public X509Certificate2? ClientCertificate { get; init; }

	/// <summary>
	/// 可选的远程证书验证回调函数。
	/// </summary>
	/// <remarks>
	/// 回调参数仅在调用期间有效，不应缓存。
	/// 如需在回调外使用远程证书，请通过 <see cref="DtlsSession.RemoteCertificate"/> 获取，并由调用方负责释放。
	/// 回调仅提供对端叶子证书；验证所需的中间证书须由调用方自行提供。
	/// <c>X509Chain</c> 由本库释放；调用方必须在回调返回前逐个释放其 <c>ChainElements</c> 中的证书。
	/// </remarks>
	public Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? RemoteCertificateValidation { get; init; }

	public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

	public SslProtocols Version { get; init; }
}
