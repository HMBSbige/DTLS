using DTLS.Dtls;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DTLS.Tests;

public class WolfSslInteropTests : InteropTestBase
{
	private static readonly string? WolfSslHome = ResolveWolfSslHome();
	private static readonly string? ServerBin = WolfSslHome is null ? null : Path.Combine(WolfSslHome, "build", "examples", "server", BinaryName("server"));
	private static readonly string? ClientBin = WolfSslHome is null ? null : Path.Combine(WolfSslHome, "build", "examples", "client", BinaryName("client"));

	private static string BinaryName(string name)
	{
		return OperatingSystem.IsWindows() ? $"{name}.exe" : name;
	}

	private static string? ResolveWolfSslHome()
	{
		string? env = Environment.GetEnvironmentVariable("WOLFSSL_HOME");

		if (env is not null)
		{
			return env;
		}

		DirectoryInfo? dir = new(AppContext.BaseDirectory);

		while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "DTLS.slnx")))
		{
			dir = dir.Parent;
		}

		if (dir?.Parent is { } parent)
		{
			string wolfDir = Path.Combine(parent.FullName, "wolfssl");

			if (Directory.Exists(wolfDir))
			{
				return wolfDir;
			}
		}

		return null;
	}

	[Test]
	public async Task Client_Dtls13Handshake_WithWolfSslServer(CancellationToken cancellationToken)
	{
		Skip.Unless(File.Exists(ServerBin), $"wolfSSL server binary not found: {ServerBin}");

		string tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
		Directory.CreateDirectory(tmpDir);

		try
		{
			(string certPath, string keyPath) = ExportPem(Cert, tmpDir);
			int port = GetFreeUdpPort();
			// -u -v 4: DTLS 1.3; -d: skip peer verification; -e: echo.
			using Process? server = Process.Start
			(
				new ProcessStartInfo
				(
					ServerBin,
					$"-u -v 4 -p {port} -c \"{certPath}\" -k \"{keyPath}\" -d -e"
				)
				{
					WorkingDirectory = WolfSslHome,
					RedirectStandardOutput = true,
					CreateNoWindow = true
				}
			);
			Assert.NotNull(server);

			try
			{
				await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);

				using UdpClient udp = new();
				UdpDatagramTransport transport = new(udp, new IPEndPoint(IPAddress.Loopback, port));

				await using DtlsTransport client = await DtlsTransport.CreateClientAsync
				(
					transport,
					new DtlsClientOptions
					{
						ServerName = "localhost",
						RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSigned(Cert, cert, chain, errors)
					},
					cancellationToken
				);

				using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
				cts.CancelAfter(TimeSpan.FromSeconds(3));

				await client.HandshakeAsync(cts.Token);
				await Assert.That(client.Session.Protocol).IsEqualTo(DtlsVersion.Dtls13);

				Memory<byte> payload = new byte[256];
				Random.Shared.NextBytes(payload.Span);

				await client.SendAsync(payload, cts.Token);

				Memory<byte> buffer = new byte[256];
				int n = await client.ReceiveAsync(buffer, cts.Token);
				await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();
			}
			finally
			{
				server.Kill(true);
			}
		}
		finally
		{
			Directory.Delete(tmpDir, true);
		}
	}

	[Test]
	public async Task Server_Dtls13Handshake_WithWolfSslClient(CancellationToken cancellationToken)
	{
		Skip.Unless(File.Exists(ClientBin), $"wolfSSL client binary not found: {ClientBin}");

		int port = GetFreeUdpPort();
		using UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, port));
		UdpDatagramTransport transport = new(udp);

		await using DtlsTransport dtlsServer = await DtlsTransport.CreateServerAsync
		(
			transport,
			new DtlsServerOptions { Certificate = Cert },
			cancellationToken
		);

		// -u -v 4: DTLS 1.3; -d: skip peer verification.
		using Process? wolfClient = Process.Start
		(
			new ProcessStartInfo
			(
				ClientBin,
				$"-u -v 4 -h 127.0.0.1 -p {port} -d"
			)
			{
				WorkingDirectory = WolfSslHome,
				RedirectStandardOutput = true,
				CreateNoWindow = true
			}
		);
		Assert.NotNull(wolfClient);

		try
		{
			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			cts.CancelAfter(TimeSpan.FromSeconds(3));

			const string message = "hello wolfssl!";
			byte[] buffer = new byte[256];
			int n = await dtlsServer.ReceiveAsync(buffer, cts.Token);
			await Assert.That(Encoding.UTF8.GetString(buffer, 0, n)).IsEqualTo(message);

			byte[] reply = "hello-from-server"u8.ToArray();
			await dtlsServer.SendAsync(reply, cts.Token);

			string output = await wolfClient.StandardOutput.ReadToEndAsync(cts.Token);
			await Assert.That(output).Contains("hello-from-server");
			await TestContext.Current!.OutputWriter.WriteLineAsync(output);
		}
		finally
		{
			wolfClient.Kill(true);
		}
	}
}
