using DTLS.Dtls;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace DTLS.Tests;

public class OpenSslInteropTests : InteropTestBase
{
	public override void SkipUnlessInteropDependencyAvailable()
	{
		Skip.Unless(IsOpensslAvailable, "openssl not found in PATH");
	}

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

	[Test]
	public async Task Client_HandshakeAndData_WithOpenSslServer(CancellationToken cancellationToken)
	{
		string tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
		Directory.CreateDirectory(tmpDir);

		try
		{
			(string certPath, string keyPath) = ExportPem(Cert, tmpDir);
			int port = GetFreeUdpPort();

			using Process? server = Process.Start
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
			);
			Assert.NotNull(server);

			try
			{
				await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);// Give server time to start

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

				using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
				cts.CancelAfter(TimeSpan.FromSeconds(3));

				await client.HandshakeAsync(cts.Token);
				await Assert.That(client.Session.Protocol).IsEqualTo(SslProtocols.Tls12);

				Memory<byte> buffer = new byte[256];

				// openssl server → our client: verify we receive data
				await server.StandardInput.FlushAsync(cts.Token);
				int n = await client.ReceiveAsync(buffer, cts.Token);
				string received = Encoding.ASCII.GetString(buffer.Span.Slice(0, n));
				await Assert.That(received).IsEqualTo(message);

				// our client → openssl server
				Memory<byte> payload = "hello-from-client"u8.ToArray();
				await client.SendAsync(payload, cts.Token);
				int r = await server.StandardOutput.BaseStream.ReadAsync(buffer, cts.Token);
				await Assert.That(buffer.Slice(0, r).Span.SequenceEqual(payload.Span)).IsTrue();
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
	public async Task Server_HandshakeAndData_WithOpenSslClient(CancellationToken cancellationToken)
	{
		int port = GetFreeUdpPort();
		using UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, port));
		UdpDatagramTransport transport = new(udp);

		await using DtlsTransport dtlsServer = await DtlsTransport.CreateServerAsync
		(
			transport,
			new DtlsServerOptions { Certificate = Cert }
		);

		using Process? opensslClient = Process.Start
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
		);
		Assert.NotNull(opensslClient);

		try
		{
			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			cts.CancelAfter(TimeSpan.FromSeconds(3));
			Memory<byte> buffer = new byte[256];

			// openssl stdin → DTLS → our server
			Memory<byte> payload = "hello-from-openssl-client"u8.ToArray();
			await opensslClient.StandardInput.BaseStream.WriteAsync(payload, cts.Token);
			await opensslClient.StandardInput.BaseStream.FlushAsync(cts.Token);

			int n = await dtlsServer.ReceiveAsync(buffer, cts.Token);
			await Assert.That(buffer.Slice(0, n).Span.SequenceEqual(payload.Span)).IsTrue();

			// our server → openssl client
			Memory<byte> reply = "hello-from-our-server"u8.ToArray();
			await dtlsServer.SendAsync(reply, cts.Token);

			int r = await opensslClient.StandardOutput.BaseStream.ReadAsync(buffer, cts.Token);
			await Assert.That(buffer.Slice(0, r).Span.SequenceEqual(reply.Span)).IsTrue();
		}
		finally
		{
			opensslClient.Kill(true);
		}
	}
}
