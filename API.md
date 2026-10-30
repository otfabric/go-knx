# API

Every exported package, its main types, and how to construct, use and close them. Signatures and options are in the package documentation; a minimal program for each use is in the [README](README.md#quick-start).

## Conventions

- Blocking calls take a `context.Context`.
- Configuration is by functional options (`tunnel.Option`, `routing.Option`, `client.Option`, …).
- Logging and metrics are injected: [OBSERVABILITY.md](OBSERVABILITY.md). Errors: [ERRORS.md](ERRORS.md).
- Everything that holds a socket has a `Close` that the caller must call; the tables below name it.

## Group communication

| Package | Construct | Use | Close |
|---|---|---|---|
| `client` | `DialTunnel(ctx, addr, topts, opts...)`, `ListenRouting(ctx, ropts, opts...)`, or `New(link, opts...)` over a `client.Link` | `GroupWrite`, `GroupRead`, `GroupReadAll`, `GroupRespond`, `Subscribe` (returns a `*Subscription` with channel `C()`); `Done`, `Err` report the end of the link | `Client.Close` |
| `client` | `Client.Device(addr, opts...)` returns a `*client.Device` | access to one device through the client; the `Connected()` option uses a transport-layer connection | `Device.Close` |
| `tunnel` | `Dial(ctx, addr, opts...)` returns a `*Conn`, UDP or TCP | tunnelling, busmonitor and feature services | `Conn.Close` |
| `routing` | `Listen(ctx, opts...)` returns a `*Conn` | routing indications on the multicast group | `Conn.Close` |
| `device` | `New(name, addr)`; `NewGroupObject(name, id, flags, addresses...)` | a virtual device: `Add`, `OnChange`, and `Handle`, `Transmit` on `cemi.LData` frames | nothing to close: it holds no socket |

## Server

| Package | Construct | Use | Close |
|---|---|---|---|
| `server` | `New(opts...)` returns a `*Server` | `Start(ctx)` or `Serve(ctx)`; answers discovery and description, accepts tunnels | `Server.Close` |
| `mgmt` | a `Responder` struct literal | device side of remote device management: `Handle(frame)` returns the answers; the application implements `Properties` and `Describer` | nothing to close |

## Discovery and management

| Package | Construct | Use | Close |
|---|---|---|---|
| `discovery` | package functions `Search(ctx, opts...)`, `Describe(ctx, addr, opts...)` | finds KNXnet/IP servers; returns `[]Result` and `knxnetip.DIBs` | nothing to close |
| `devmgmt` | `Dial(ctx, addr, opts...)` returns a `*Conn` (uses `tunnel` options) | reads and writes interface object properties; `*PropertyError` | `Conn.Close` |
| `mgmt` | `ParseProperty(tpdu)`, `DescriptorTPDU(tpci)` | services of remote device management | no connection of its own |

## Security

| Package | Construct | Use |
|---|---|---|
| `keyring` | `LoadFile(path, password)`, `Load(r, password)`, `Parse(b, password)` | reads `.knxkeys` files into a `*Keyring` |
| `secure` | `NewCredentials`, `NewKeyPair`, `NewSession`, `NewRoutingTimer` | KNX IP Secure: key derivation and the session handshake |
| `datasecure` | `NewTable(keys, senders, seq)`, `Open`, `OpenSyncRequest`, `OpenSyncResponse` | KNX Data Secure for group communication |

These hold no sockets and have nothing to close.

## Codecs

Pure encode and decode, with no I/O and nothing to close.

| Package | Main contents |
|---|---|
| `knx` (root) | `IndividualAddress`, `GroupAddress` and their `Parse…`, `MustParse…` functions, `Priority`, `State`, `Logger`, `Metrics`, sentinel errors |
| `knxnetip` | KNXnet/IP frames: header, HPAI, DIBs, core, tunnelling, routing and secure bodies |
| `cemi` | cEMI frames, `LData` |
| `apdu` | TPCI and APCI, `TPDU` |
| `dpt` | Datapoint types: `Get(id)` returns a `*Type`, which encodes and decodes application values |
