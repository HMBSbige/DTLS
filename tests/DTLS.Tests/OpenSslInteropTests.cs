using DTLS.Dtls;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace DTLS.Tests;

public class OpenSslInteropTests : InteropTestBase
{
	private static readonly bool IsOpensslAvailable = CheckOpenSsl();

	private static bool CheckOpenSsl()
	{
		try
		{
			using Process? p = Process.Start
			(
				new ProcessStartInfo("openssl", "version") { CreateNoWindow = true }
			);
			return p is not null && p.WaitForExit(TimeSpan.FromSeconds(1)) && p.ExitCode is 0;
		}
		catch
		{
			return false;
		}
	}

	[Fact]
	public async Task Client_HandshakeAndData_WithOpenSslServer()
	{
		Assert.SkipUnless(IsOpensslAvailable, "openssl not found in PATH");

		string tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
		Directory.CreateDirectory(tmpDir);

		try
		{
			(string certPath, string keyPath) = ExportPem(Cert, tmpDir);
			int port = GetFreeUdpPort();

			using Process server = Process.Start
			(
				new ProcessStartInfo
				(
					"openssl",
					$"s_server -4 -dtls1_2 -accept {port} " +
					$"-cert \"{certPath}\" -key \"{keyPath}\" -quiet"
				)
				{
					RedirectStandardInput = true,
					RedirectStandardOutput = true,
					CreateNoWindow = true
				}
			)!;

			try
			{
				await Task.Delay(TimeSpan.FromMilliseconds(100), TestContext.Current.CancellationToken);// Give server time to start

				using UdpClient udp = new();
				UdpDatagramTransport transport = new(udp, new IPEndPoint(IPAddress.Loopback, port));

				await using DtlsTransport client = await DtlsTransport.CreateClientAsync
				(
					transport,
					new DtlsClientOptions
					{
						ServerName = "localhost",
						RemoteCertificateValidation = (cert, chain, errors) => TestCertificateFactory.ValidateSelfSigned(Cert, cert, chain, errors)
					}
				);

				const string message = "hello-from-server";
				await server.StandardInput.WriteAsync(message);// Trigger server handshake

				using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
				cts.CancelAfter(TimeSpan.FromSeconds(3));

				await client.HandshakeAsync(cts.Token);
				Assert.Equal(SslProtocols.Tls12, client.Session.Protocol);

				Memory<byte> buffer = new byte[256];

				// openssl server → our client: verify we receive data
				await server.StandardInput.FlushAsync(cts.Token);
				int n = await client.ReceiveAsync(buffer, cts.Token);
				string received = Encoding.ASCII.GetString(buffer.Span.Slice(0, n));
				Assert.Equal(message, received);

				// our client → openssl server
				Memory<byte> payload = "hello-from-client"u8.ToArray();
				await client.SendAsync(payload, cts.Token);
				int r = await server.StandardOutput.BaseStream.ReadAsync(buffer, cts.Token);
				Assert.Equal(payload, buffer.Slice(0, r));
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

	[Fact]
	public async Task Server_HandshakeAndData_WithOpenSslClient()
	{
		Assert.SkipUnless(IsOpensslAvailable, "openssl not found in PATH");

		int port = GetFreeUdpPort();
		using UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, port));
		UdpDatagramTransport transport = new(udp);

		await using DtlsTransport dtlsServer = await DtlsTransport.CreateServerAsync
		(
			transport,
			new DtlsServerOptions { Certificate = Cert }
		);

		using Process opensslClient = Process.Start
		(
			new ProcessStartInfo
			(
				"openssl",
				$"s_client -dtls1_2 -connect 127.0.0.1:{port} -quiet"
			)
			{
				RedirectStandardInput = true,
				RedirectStandardOutput = true,
				CreateNoWindow = true
			}
		)!;

		try
		{
			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
			cts.CancelAfter(TimeSpan.FromSeconds(3));
			Memory<byte> buffer = new byte[256];

			// openssl stdin → DTLS → our server
			Memory<byte> payload = "hello-from-openssl-client"u8.ToArray();
			await opensslClient.StandardInput.BaseStream.WriteAsync(payload, cts.Token);
			await opensslClient.StandardInput.BaseStream.FlushAsync(cts.Token);

			int n = await dtlsServer.ReceiveAsync(buffer, cts.Token);
			Assert.Equal(payload, buffer.Slice(0, n));

			// our server → openssl client
			Memory<byte> reply = "hello-from-our-server"u8.ToArray();
			await dtlsServer.SendAsync(reply, cts.Token);

			int r = await opensslClient.StandardOutput.BaseStream.ReadAsync(buffer, cts.Token);
			Assert.Equal(reply, buffer.Slice(0, r));
		}
		finally
		{
			opensslClient.Kill(true);
		}
	}
}
