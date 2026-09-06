using DTLS.Common;
using DTLS.Dtls;
using System.Buffers.Binary;
using System.Security.Cryptography.X509Certificates;

// ReSharper disable AccessToDisposedClosure

namespace DTLS.Tests;

public class DtlsSessionContractTests : DtlsTestBase
{
	[Test]
	[Arguments(DtlsVersion.Dtls12)]
	[Arguments(DtlsVersion.Dtls13)]
	public async Task Feed_AuthenticatesOnceAndReleasesCallbackChain(DtlsVersion protocol)
	{
		int validationCount = 0;
		X509Certificate2[] chainCertificates = [];
		using SessionPair pair = new
		(
			new DtlsClientOptions
			{
				ServerName = "localhost",
				MinVersion = protocol,
				MaxVersion = protocol,
				RemoteCertificateValidation = (certificate, chain, errors) =>
				{
					validationCount++;
					chainCertificates = chain?.ChainElements.Select(element => element.Certificate).ToArray() ?? [];
					return TestCertificateFactory.ValidateSelfSigned(Cert, certificate, chain, errors);
				}
			}, new DtlsServerOptions
			{
				Certificate = Cert,
				MinVersion = protocol,
				MaxVersion = protocol
			}
		);

		await Assert.That(pair.Client.Protocol).IsNull();
		using X509Certificate2? beforeHandshake = pair.Client.GetRemoteCertificate();
		await Assert.That(beforeHandshake).IsNull();

		pair.Pump();
		await Assert.That(pair.Client.Protocol).IsEqualTo(protocol);
		await Assert.That(pair.Server.Protocol).IsEqualTo(protocol);
		await Assert.That(chainCertificates).IsNotEmpty();
		await Assert.That(chainCertificates).All(certificate => certificate.Handle == nint.Zero);

		byte[] received = new byte[32];
		await Assert.That(pair.Server.TryReceive(received, out int emptyLength)).IsFalse();
		await Assert.That(emptyLength).IsEqualTo(0);

		pair.SendFromClient("authenticated"u8);
		await Assert.That(pair.Server.TryReceive(received, out int receivedLength)).IsTrue();
		await Assert.That(received.AsSpan(0, receivedLength).SequenceEqual("authenticated"u8)).IsTrue();
		await Assert.That(pair.Server.TryReceive(received, out _)).IsFalse();
		await Assert.That(validationCount).IsEqualTo(1);
	}

	[Test]
	public async Task Feed_RejectsUntrustedPeerAndPermanentlyEndsSession()
	{
		using SessionPair pair = new(new DtlsClientOptions { ServerName = "localhost" }, new DtlsServerOptions { Certificate = Cert });

		await Assert.That(() => pair.Pump()).Throws<CertificateException>();
		await AssertSessionEndedAsync(pair.Client);
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task Feed_CallbackFailureReleasesChainAndPermanentlyEndsSession(bool throwFromCallback)
	{
		X509Certificate2[] chainCertificates = [];
		using SessionPair pair = new
		(
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, chain, _) =>
				{
					chainCertificates = chain?.ChainElements.Select(element => element.Certificate).ToArray() ?? [];
					return throwFromCallback ? throw new InvalidOperationException("Validation callback failed.") : false;
				}
			}, new DtlsServerOptions { Certificate = Cert }
		);

		if (throwFromCallback)
		{
			await Assert.That(() => pair.Pump()).Throws<InvalidOperationException>();
		}
		else
		{
			await Assert.That(() => pair.Pump()).Throws<CertificateException>();
		}

		await Assert.That(chainCertificates).IsNotEmpty();
		await Assert.That(chainCertificates).All(certificate => certificate.Handle == nint.Zero);
		await AssertSessionEndedAsync(pair.Client);
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task Feed_CallbackChangesChain_ReleasesOriginalAndCurrentCertificates(bool rebuildChain)
	{
		X509Certificate2[] originalCertificates = [];
		X509Certificate2[] currentCertificates = [];
		using SessionPair pair = new
		(
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (certificate, chain, _) =>
				{
					if (certificate is null || chain is null)
					{
						return false;
					}

					originalCertificates = chain.ChainElements.Select(element => element.Certificate).ToArray();

					if (rebuildChain)
					{
						chain.Build(certificate);
					}
					else
					{
						chain.Reset();
					}

					currentCertificates = chain.ChainElements.Select(element => element.Certificate).ToArray();
					return true;
				}
			}, new DtlsServerOptions { Certificate = Cert }
		);

		try
		{
			pair.Pump();
			await Assert.That(originalCertificates).IsNotEmpty();
			await Assert.That(currentCertificates.Length > 0).IsEqualTo(rebuildChain);
			await Assert.That(currentCertificates).All(certificate => certificate.Handle == nint.Zero);
			await Assert.That(originalCertificates).All(certificate => certificate.Handle == nint.Zero);
		}
		finally
		{
			foreach (X509Certificate2 certificate in originalCertificates.Concat(currentCertificates))
			{
				certificate.Dispose();
			}
		}
	}

	[Test]
	public async Task Feed_CallbackCannotDriveSession()
	{
		DtlsSession? callbackSession = null;
		bool reentrantCloseAccepted = false;
		using SessionPair pair = new
		(
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) =>
				{
					// ReSharper disable once AccessToModifiedClosure
					DtlsSession session = callbackSession ?? throw new InvalidOperationException("Session has not been created.");
					session.Close(new byte[65536]);
					reentrantCloseAccepted = true;
					return true;
				}
			}, new DtlsServerOptions { Certificate = Cert }
		);
		callbackSession = pair.Client;

		await Assert.That(() => pair.Pump()).Throws<InvalidOperationException>();
		await Assert.That(reentrantCloseAccepted).IsFalse();
		await AssertSessionEndedAsync(pair.Client);
	}

	[Test]
	public async Task RemoteCertificateCopies_HaveIndependentLifetimes()
	{
		using SessionPair pair = new
		(
			new DtlsClientOptions
			{
				ServerName = "localhost",
				RemoteCertificateValidation = (_, _, _) => true
			}, new DtlsServerOptions { Certificate = Cert }
		);
		pair.Pump();

		using (X509Certificate2? first = pair.Client.GetRemoteCertificate())
		{
			await Assert.That(first).IsNotNull();
			await Assert.That(first.RawDataMemory.Span.SequenceEqual(Cert.RawDataMemory.Span)).IsTrue();
		}

		using X509Certificate2? second = pair.Client.GetRemoteCertificate();
		await Assert.That(second).IsNotNull();
		await Assert.That(second.RawDataMemory.Span.SequenceEqual(Cert.RawDataMemory.Span)).IsTrue();

		pair.SendFromClient("still connected"u8);
		byte[] received = new byte[32];
		await Assert.That(pair.Server.TryReceive(received, out int receivedLength)).IsTrue();
		await Assert.That(received.AsSpan(0, receivedLength).SequenceEqual("still connected"u8)).IsTrue();

		pair.Client.Dispose();
		await Assert.That(second.RawDataMemory.Span.SequenceEqual(Cert.RawDataMemory.Span)).IsTrue();
		await Assert.That(() => pair.Client.GetRemoteCertificate()).Throws<ObjectDisposedException>();
	}

	private static async Task AssertSessionEndedAsync(DtlsSession session)
	{
		byte[] output = new byte[65536];
		await Assert.That(session.Protocol).IsNull();
		await Assert.That(() => session.Feed([], output)).Throws<ObjectDisposedException>();
		await Assert.That(() => session.HandleTimeout(output)).Throws<ObjectDisposedException>();
		await Assert.That(() => session.Send("rejected"u8, output)).Throws<ObjectDisposedException>();
		await Assert.That(() => session.TryReceive(output, out _)).Throws<ObjectDisposedException>();
	}

	private sealed class SessionPair : IDisposable
	{
		private readonly byte[] _output = new byte[65536];
		private readonly Queue<(DtlsSession Destination, byte[] Datagram)> _pending = new();

		public DtlsSession Client { get; }

		public DtlsSession Server { get; }

		public SessionPair(DtlsClientOptions clientOptions, DtlsServerOptions serverOptions)
		{
			(DtlsSession client, DtlsOpResult clientResult) = DtlsSession.CreateClient(clientOptions, _output);
			Client = client;

			try
			{
				byte[] clientFlight = _output.AsSpan(0, clientResult.BytesWritten).ToArray();
				(DtlsSession server, DtlsOpResult serverResult) = DtlsSession.CreateServer(serverOptions, _output);
				Server = server;
				Enqueue(Client, _output.AsSpan(0, serverResult.BytesWritten));
				Enqueue(Server, clientFlight);
			}
			catch
			{
				Client.Dispose();
				throw;
			}
		}

		public void Pump()
		{
			int packets = 0;

			while (_pending.TryDequeue(out var pending))
			{
				if (++packets > 64)
				{
					throw new InvalidOperationException("Handshake did not converge after 64 packets.");
				}

				DtlsOpResult result = pending.Destination.Feed(pending.Datagram, _output);
				Enqueue(pending.Destination == Client ? Server : Client, _output.AsSpan(0, result.BytesWritten));
			}

			if (Client.IsHandshaking || Server.IsHandshaking)
			{
				throw new InvalidOperationException("Handshake stalled without a pending datagram.");
			}
		}

		public void SendFromClient(ReadOnlySpan<byte> plaintext)
		{
			DtlsOpResult result = Client.Send(plaintext, _output);
			Enqueue(Server, _output.AsSpan(0, result.BytesWritten));
			Pump();
		}

		private void Enqueue(DtlsSession destination, ReadOnlySpan<byte> framed)
		{
			while (!framed.IsEmpty)
			{
				ushort length = BinaryPrimitives.ReadUInt16LittleEndian(framed);
				framed = framed.Slice(sizeof(ushort));
				_pending.Enqueue((destination, framed.Slice(0, length).ToArray()));
				framed = framed.Slice(length);
			}
		}

		public void Dispose()
		{
			Client.Dispose();
			Server.Dispose();
		}
	}
}
