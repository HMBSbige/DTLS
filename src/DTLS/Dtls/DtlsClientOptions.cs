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
	/// 回调参数仅用于当前调用内的即时判断，不应缓存或跨调用保存其对象引用。
	/// 如需在回调外使用叶子证书，必须通过 <see cref="DtlsSession.RemoteCertificate"/> 重新获取证书实例，并由调用方负责 dispose。
	/// <c>X509Chain</c> 对象会自动释放；启用回调时，调用方必须逐个释放 <c>X509Chain.ChainElements</c> 和 <c>ChainPolicy.ExtraStore</c> 中的证书对象（建议在回调返回前完成）。
	/// </remarks>
	public Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? RemoteCertificateValidation { get; init; }

	public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

	public SslProtocols Version { get; init; }
}
