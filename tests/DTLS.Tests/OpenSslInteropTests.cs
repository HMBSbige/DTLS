using DTLS.Dtls;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DTLS.Tests;

public class OpenSslInteropTests : DtlsTestBase
{
	private static readonly ReadOnlyMemory<byte> FromOpenSsl = "hello-from-openssl"u8.ToArray();
	private static readonly ReadOnlyMemory<byte> FromDtls = "hello-from-dtls"u8.ToArray();
	private static readonly string OpenSslBin = Environment.GetEnvironmentVariable("OPENSSL_BIN") is { Length: > 0 } bin ? bin : "openssl";

	// Lists every protocol flag the build supports; null when openssl cannot start.
	private static readonly string? ServerUsage = GetServerUsage();

	[Before(Test)]
	public void SkipUnlessOpenSslAvailable()
	{
		Skip.Unless(ServerUsage is not null, $"openssl not found: {OpenSslBin}");
	}

	private static string? GetServerUsage()
	{
		ProcessStartInfo startInfo = new(OpenSslBin, "s_server -help") { RedirectStandardError = true, CreateNoWindow = true };

		try
		{
			using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {OpenSslBin}");
			string usage = process.StandardError.ReadToEnd();
			process.WaitForExit();
			// The exit code is ignored: LibreSSL exits with 1 after printing the usage.
			return usage;
		}
		catch (Win32Exception)
		{
			return null;
		}
	}

	private static string GetVersionFlag(DtlsVersion version)
	{
		string flag = version switch
		{
			DtlsVersion.Dtls12 => "-dtls1_2",
			DtlsVersion.Dtls13 => "-dtls1_3",
			_ => throw new ArgumentOutOfRangeException(nameof(version))
		};
		Skip.Unless(ServerUsage?.Contains(flag) is true, $"{OpenSslBin} does not support {flag}");
		return flag;
	}

	private static (string certPath, string keyPath) ExportPem(X509Certificate2 cert, string dir)
	{
		string certPath = Path.Combine(dir, "cert.pem");
		string keyPath = Path.Combine(dir, "key.pem");
		File.WriteAllText(certPath, cert.ExportCertificatePem());
		using ECDsa key = cert.GetECDsaPrivateKey() ?? throw new ArgumentException("Certificate has no ECDSA private key.", nameof(cert));
		File.WriteAllText(keyPath, key.ExportECPrivateKeyPem());
		return (certPath, keyPath);
	}

	private static int GetFreeUdpPort()
	{
		using Socket s = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
		s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
		return s.LocalEndPoint is IPEndPoint { Port: var port } ? port : throw new InvalidOperationException("Socket is not bound.");
	}

	// Expects FromOpenSsl to be already queued on openssl's stdin.
	private static async Task AssertExchangeAsync(OpenSslProcess openssl, DtlsTransport dtls, CancellationToken cancellationToken)
	{
		Memory<byte> buffer = new byte[256];

		int n = await dtls.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(FromOpenSsl.Span)).IsTrue();

		await dtls.SendAsync(FromDtls, cancellationToken);
		n = await openssl.ReceiveAsync(buffer, cancellationToken);
		await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(FromDtls.Span)).IsTrue();
	}

	[Test]
	[Arguments(DtlsVersion.Dtls12)]
	[Arguments(DtlsVersion.Dtls13)]
	public async Task Client_HandshakeAndData_WithOpenSslServer(DtlsVersion version, CancellationToken cancellationToken)
	{
		string versionFlag = GetVersionFlag(version);
		DirectoryInfo tmpDir = Directory.CreateTempSubdirectory();

		try
		{
			(string certPath, string keyPath) = ExportPem(Cert, tmpDir.FullName);
			int port = GetFreeUdpPort();
			await using OpenSslProcess server = OpenSslProcess.Start($"s_server -4 {versionFlag} -accept {port} -cert \"{certPath}\" -key \"{keyPath}\" -quiet");
			await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);

			using UdpClient udp = new();
			UdpDatagramTransport transport = new(udp, new IPEndPoint(IPAddress.Loopback, port));
			DtlsClientOptions options = new()
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSigned(Cert, cert, chain, errors)
			};
			await using DtlsTransport client = await DtlsTransport.CreateClientAsync(transport, options, cancellationToken);

			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			cts.CancelAfter(TimeSpan.FromSeconds(3));

			// On Windows the handshake stalls if the server's message is queued only after it.
			await server.SendAsync(FromOpenSsl, cts.Token);
			await client.HandshakeAsync(cts.Token);
			await Assert.That(client.Session.Protocol).IsEqualTo(version);
			await AssertExchangeAsync(server, client, cts.Token);
		}
		finally
		{
			tmpDir.Delete(true);
		}
	}

	[Test]
	[Arguments(DtlsVersion.Dtls12)]
	[Arguments(DtlsVersion.Dtls13)]
	public async Task Server_HandshakeAndData_WithOpenSslClient(DtlsVersion version, CancellationToken cancellationToken)
	{
		string versionFlag = GetVersionFlag(version);
		int port = GetFreeUdpPort();
		using UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, port));
		UdpDatagramTransport transport = new(udp);

		await using DtlsTransport server = await DtlsTransport.CreateServerAsync(transport, new DtlsServerOptions { Certificate = Cert }, cancellationToken);
		await using OpenSslProcess client = OpenSslProcess.Start($"s_client {versionFlag} -connect 127.0.0.1:{port} -quiet");

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		cts.CancelAfter(TimeSpan.FromSeconds(3));

		await client.SendAsync(FromOpenSsl, cts.Token);
		// The server handshake completes inside the first ReceiveAsync.
		await AssertExchangeAsync(client, server, cts.Token);
		await Assert.That(server.Session.Protocol).IsEqualTo(version);
	}

	private sealed class OpenSslProcess(Process process) : IAsyncDisposable
	{
		public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
		{
			await process.StandardInput.BaseStream.WriteAsync(data, cancellationToken);
			await process.StandardInput.BaseStream.FlushAsync(cancellationToken);
		}

		public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
		{
			return process.StandardOutput.BaseStream.ReadAsync(buffer, cancellationToken);
		}

		public static OpenSslProcess Start(string arguments)
		{
			ProcessStartInfo startInfo = new(OpenSslBin, arguments)
			{
				RedirectStandardInput = true,
				RedirectStandardOutput = true,
				CreateNoWindow = true
			};
			return new OpenSslProcess(Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {OpenSslBin}"));
		}

		public async ValueTask DisposeAsync()
		{
			if (!process.HasExited)
			{
				process.Kill(true);
			}

			await process.WaitForExitAsync();
			process.Dispose();
		}
	}
}
