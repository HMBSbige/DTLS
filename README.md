# DTLS

[![NuGet](https://img.shields.io/nuget/v/DTLS.svg?logo=nuget)](https://www.nuget.org/packages/DTLS)

High-performance DTLS (Datagram Transport Layer Security) library for .NET.

## Usage

`datagrams` is an `IDatagramTransport` for one peer. Use `cancellationToken` to cancel the operations.

### Client

```csharp
using DTLS.Dtls;
using System.Text;

DtlsClientOptions options = new() { ServerName = "example.com" };

using DtlsTransport client = await DtlsTransport.CreateClientAsync(datagrams, options, cancellationToken);
await client.HandshakeAsync(cancellationToken);

await client.SendAsync("Hello, DTLS!"u8.ToArray(), cancellationToken);

byte[] buffer = new byte[65536];
int length = await client.ReceiveAsync(buffer, cancellationToken);
Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, length));

await client.CloseAsync(cancellationToken);
```

Server certificates are validated during the handshake. Set `RemoteCertificateValidation` to customize validation.

### Server

```csharp
using DTLS.Dtls;

DtlsServerOptions options = new() { Certificate = serverCertificate };

using DtlsTransport server = await DtlsTransport.CreateServerAsync(datagrams, options, cancellationToken);
await server.HandshakeAsync(cancellationToken);

byte[] buffer = new byte[65536];
int length = await server.ReceiveAsync(buffer, cancellationToken);
if (length > 0)
{
    await server.SendAsync(buffer.AsMemory(0, length), cancellationToken);
}

await server.CloseAsync(cancellationToken);
```

`serverCertificate` must contain an exportable ECDSA private key.

Dispose the underlying transport and supplied certificates yourself.

## API

| Type | Purpose |
| --- | --- |
| [DtlsTransport](src/DTLS/Dtls/DtlsTransport.cs) | Asynchronous handshake, send, receive, and close operations. |
| [DtlsSession](src/DTLS/Dtls/DtlsSession.cs) | Protocol processing when you manage I/O and timers yourself. |
| [IDatagramTransport](src/DTLS/Common/IDatagramTransport.cs) | Transport interface that preserves datagram boundaries. |
| [DtlsClientOptions](src/DTLS/Dtls/DtlsClientOptions.cs) | Server name and optional client certificate. |
| [DtlsServerOptions](src/DTLS/Dtls/DtlsServerOptions.cs) | Server certificate and client authentication. |
| [DtlsVersion](src/DTLS/Dtls/DtlsVersion.cs) | Protocol versions for `MinVersion` and `MaxVersion`. |

## License

[MIT](LICENSE)
