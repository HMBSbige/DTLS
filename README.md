# DTLS

[![NuGet](https://img.shields.io/nuget/v/DTLS.svg?logo=nuget)](https://www.nuget.org/packages/DTLS)

High-performance DTLS (Datagram Transport Layer Security) library for .NET, powered by a native Rust backend.

- Sans-I/O design for maximum flexibility
- AOT compatible
- DTLS 1.2 / 1.3 support

## Usage

### Client

```csharp
var options = new DtlsClientOptions
{
    ServerName = "example.com",
    RemoteCertificateValidation = (cert, chain, errors) => true,
};

await using var transport = await DtlsTransport.CreateClientAsync(udpTransport, options);
await transport.HandshakeAsync();

await transport.SendAsync(data);
var bytesRead = await transport.ReceiveAsync(buffer);
```

### Server

```csharp
var options = new DtlsServerOptions
{
    Certificate = serverCert,
};

await using var transport = await DtlsTransport.CreateServerAsync(udpTransport, options);
await transport.HandshakeAsync();

var bytesRead = await transport.ReceiveAsync(buffer);
await transport.SendAsync(response);
```

## API

### IDatagramTransport

Low-level datagram transport abstraction that preserves message boundaries.

```csharp
public interface IDatagramTransport
{
    ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);
    ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default);
}
```

### DtlsTransport

Async I/O wrapper that bridges the sans-I/O protocol engine with an `IDatagramTransport`.

| Method              | Description                |
| ------------------- | -------------------------- |
| `CreateClientAsync` | Create a DTLS client       |
| `CreateServerAsync` | Create a DTLS server       |
| `HandshakeAsync`    | Perform DTLS handshake     |
| `SendAsync`         | Send encrypted datagram    |
| `ReceiveAsync`      | Receive decrypted datagram |

### DtlsSession

Sans-I/O DTLS protocol engine for advanced scenarios.

| Method          | Description                            |
| --------------- | -------------------------------------- |
| `CreateClient`  | Create a client session                |
| `CreateServer`  | Create a server session                |
| `Feed`          | Feed received data into the engine     |
| `HandleTimeout` | Handle retransmission timeout          |
| `Send`          | Encrypt plaintext into output          |
| `TryReceive`    | Try to read decrypted application data |
| `VerifyPeer`    | Verify peer certificate                |

### Options

`DtlsClientOptions` — Client configuration:

| Property                      | Description                            |
| ----------------------------- | -------------------------------------- |
| `ServerName`                  | Required. Server hostname for SNI      |
| `ClientCertificate`           | Optional client certificate            |
| `RemoteCertificateValidation` | Custom certificate validation callback |
| `HandshakeTimeout`            | Handshake timeout (default 15s)        |
| `Version`                     | SSL/TLS protocol version               |

`DtlsServerOptions` — Server configuration:

| Property                      | Description                                   |
| ----------------------------- | --------------------------------------------- |
| `Certificate`                 | Required. Server certificate with private key |
| `RemoteCertificateValidation` | Custom certificate validation callback        |
| `HandshakeTimeout`            | Handshake timeout (default 15s)               |
| `Version`                     | SSL/TLS protocol version                      |
| `RequireClientCertificate`    | Whether to require client certificate         |

## License

[MIT](LICENSE)
