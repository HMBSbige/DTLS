using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

public abstract class InteropTestBase : DtlsTestBase
{
	protected static (string certPath, string keyPath) ExportPem(X509Certificate2 cert, string dir)
	{
		string certPath = Path.Combine(dir, "cert.pem");
		string keyPath = Path.Combine(dir, "key.pem");
		File.WriteAllText(certPath, cert.ExportCertificatePem());
		File.WriteAllText(keyPath, cert.GetECDsaPrivateKey()!.ExportECPrivateKeyPem());
		return (certPath, keyPath);
	}

	protected static int GetFreeUdpPort()
	{
		using Socket s = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
		s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
		return ((IPEndPoint)s.LocalEndPoint!).Port;
	}
}
