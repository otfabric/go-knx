# go-knx Releases

Releases are made with the Release workflow (Actions → Release → bump):
it computes the version, tags it and publishes this file's section of
that version as the release notes. Add the section, headed exactly
`## vX.Y.Z` and closed by a line `---`, before running it.

## v0.8.0

**Date:** 2026-11-06
**Previous release:** v0.7.0

## Summary

Gaps found by comparing go-knx with xknx 4.1.1 (otfabric/knx-interop#19): routing flow control, TCP frame resynchronisation, a foreign-channel DISCONNECT_REQUEST, KNX IP Secure session timers, PropertyDescription and 30 more datapoint types.

**Upgrade notes:** `mgmt.Description.Type` is now `mgmt.PDT` (was `uint8`), and `Description` has an `Object` field: code that assigns a typed `uint8` to `Type` needs a conversion. A go-knx server now ends KNX IP Secure sessions idle for 60 s (was the 120 s connection alive time; `server.WithSecureSessionTimeout`). Routing senders are paced at the configured rate instead of in bursts, so a burst of indications now takes rate-limited time.

## Changes

### Added

- `client.Device.PropertyDescription` (A_PropertyDescription_Read), connectionless, connected and with the tool key. `mgmt.PDT` with the property datatypes, `Size` and `String`; `mgmt.ParseDescription`, `mgmt.DescriptionReadTPDU`, `Description.Data`, `TPDU`, `ReadLevel`, `WriteLevel`.
- Datapoint types 5.100, 15.000, 20.107, 21.002, 21.100-21.106, 21.601, 21.1000, 21.1001, 21.1010, 21.1200, 21.1201, 22.100, 22.101, 22.103, 22.1000, 22.1010, 27.001, 217.001, 222.100, 222.101, 234.001, 234.002, 275.100, 275.101, with the values `AccessData`, `OnOffInfo`, `Version` and `RoomSetpoints`. The new encodings decode to the same values in xknx 4.1.1.
- `server.WithSecureSessionTimeout` (default 60 s, `DefaultSecureSessionTimeout`) and `tunnel.WithSessionKeepAlive` (default 30 s, `DefaultSessionKeepAlive`).

### Changed

- The tunnel client sends its KNX IP Secure keep alive after 30 s idle (was a fixed 45 s).
- The server queues its outgoing routing indications (bounded by `WithQueueSize`) and paces them, instead of dropping what exceeded the rate; a full queue is still counted as `OnDropped("routing_rate")`.

### Fixed

- Routing flow control (Routing, ROUTING_BUSY): the client only waited out the last busy frame's wait time and could send 50 indications back to back; the server ignored ROUTING_BUSY. Both now count busy frames (more than 10 ms apart, the first included), wait the wait time plus a random 0..N x 50 ms, slow down afterwards and keep a minimum gap of 1/rate between indications.
- The server closed a TCP connection, and the client a KNX IP Secure tunnel over TCP, on one frame whose body did not parse, although its valid header framed it. Such a frame is now dropped and the connection kept.
- The tunnel client ignored a DISCONNECT_REQUEST for another channel; it now answers E_CONNECTION_ID and keeps the tunnel.
- The server expired idle KNX IP Secure sessions after the 120 s tunnelling alive time instead of the 60 s session timeout.

### Documentation

- `tunnel.Conn.Send` and ERRORS.md: a frame lost with the tunnel is not resent after a reconnect; the caller decides whether to repeat it.

---

## v0.7.0

**Date:** 2026-11-05
**Previous release:** v0.6.0

## Summary

Bounds for every call that waits for a peer or collects its answers. Found while hardening knxctl, which had to work around them. API.md has a new Bounds section.

**Upgrade notes:** `GroupReadAll` and `Search` now stop at a limit (1000 responses, 256 servers): raise it with `WithMaxResponses` or `WithMaxResults`. devmgmt calls without a context deadline now end after 3 s.

## Changes

### Added

- `client.WithMaxResponses`, `client.DefaultMaxResponses`, `discovery.WithMaxResults`, `discovery.DefaultMaxResults`, `devmgmt.DefaultTimeout`, `client.MaxPropertyData`.

### Fixed

- `discovery.Search` kept every distinct answer, so a flood of SEARCH_RESPONSEs grew memory for the whole timeout. It now returns once it has `DefaultMaxResults` servers (`WithMaxResults`).
- `client.GroupReadAll` kept every response. It now returns once it has `DefaultMaxResponses` (`WithMaxResponses`).
- devmgmt `PropRead`/`PropWrite` waited as long as the context lived. A server that acknowledged the request and never confirmed it blocked a caller without a deadline for ever. They now end after `DefaultTimeout` with `knx.ErrTimeout`.
- `client.Device` reported a cancelled context as `knx.ErrTimeout` ("no answer"). It now returns an error matching `context.Canceled`. An expired deadline still matches `knx.ErrTimeout` and now also `context.DeadlineExceeded`.
- `tunnel.Conn.Send` (and devmgmt, client over a tunnel): a frame too long for a KNXnet/IP datagram, or too long once wrapped by KNX IP Secure, was counted as a failed write. The connection was torn down (or reconnected) and the caller got `knx.ErrConnectionLost`. It now returns `knx.ErrInvalidValue`, sends nothing and keeps the connection.
- `client.Device.PropertyWrite` refuses data over `MaxPropertyData` (250 octets) before sending.

---

## v0.6.0

**Date:** 2026-11-04
**Previous release:** v0.5.2

## Summary

Static analysis (gosec, opengrep) at low/low is clean: every finding was fixed in the code, none was recorded as accepted. The work found defects where lengths and counters wrapped, and new hostile-peer, chaos and fuzz tests found a server defect on reconnects and a spoofing gap. Go 1.26 is now the minimum version.

**Upgrade notes:** Go 1.26 or later. No API signatures changed. See Changed for the stricter behaviour of the server and client.

## Changes

### Fixed

- `server`: a repeated CONNECT_REQUEST from the same endpoints (a client reconnecting from its socket, e.g. `tunnel.WithReconnect`) got its old channel with stale sequence counters. The client's first telegram was then acknowledged as a repetition and dropped, and the server's next request was ignored. The connection now restarts at sequence 0 and keeps its channel and individual address. Frames still queued for the old connection are dropped.
- `server`: frames of a channel (TUNNELLING_REQUEST/ACK, CONNECTIONSTATE_REQUEST, DISCONNECT_REQUEST) were accepted from any port of the client's IP address. They are now accepted only from the connection's recorded control or data endpoint, address and port.
- `discovery`, `tunnel` (Windows): a datagram larger than the receive buffer (WSAEMSGSIZE), or an ICMP port unreachable reported on the next read (WSAECONNRESET), ended `Search`, `Describe` or a secure tunnel's handshake with an error. It is now dropped and reading continues until the deadline. Found by the new hostile tests on the Windows runner.
- `tunnel`: `Send` could return a bare "use of closed network connection" error. It now returns an error matching `knx.ErrClosed` or `knx.ErrConnectionLost`, with the cause wrapped.
- `knxnetip`: structure lengths that do not fit their length octet (a DIB, CRI, CRD or SRP of 256 octets or more) wrapped modulo 256, and the wrapped frame decoded as different structures. `Marshal` and `Append` now return `ErrInvalidValue`. `AppendTo` and `AppendHeader` write the length 0, which every decoder refuses.
- `knxnetip`: `AppendHeader` wrapped a total length above 65535, for example to 6.
- `secure`: the routing timer wrapped at 48 bits. A TIMER_NOTIFY at 2^48−1 set it back to a few milliseconds, after which peers refused every frame. It now saturates.
- `secure`: the TIMER_NOTIFY message tag, which the time keeper's answer must echo, and the notify delay came from math/rand. They now come from crypto/rand.
- `secure`: `Open` refuses a wrapper longer than `knxnetip.MaxFrameLen`. Before, the length in the first CCM block wrapped.
- `mgmt`: the maximum element count of a property description is 12 bits on the wire and was masked, so 4096 was described as 0. It now saturates at 4095.
- `internal/mcast` (macOS, BSD): a multicast TTL of 256 or more wrapped to 0. It is refused (the public options already limit it to 1..255).
- `datasecure`: `NewTable` with the system clock before the sequence epoch (2018-01-05) now gives a clear error.
- `interop/node`: `--object`, `--pid`, `--start` and `--count` out of range were truncated (`--pid 300` read PID 44). They are refused.

### Changed

- Go 1.26 minimum (CI on 1.26 and 1.27), `go fix` applied.
- Tests: fuzz targets for secure, datasecure, keyring, mgmt, the server (UDP datagrams and TCP stream) and the tunnel client. New e2e suites for hostile peers and deterministic chaos. See TESTING.md.
- knx-interop v0.7.1 images (same contract 1.4), shared workflows v3.3.1.

---

## v0.5.2

**Date:** 2026-10-31
**Previous release:** v0.5.1

### Changed

- Policy 1.2: build output in `bin/` and `release/`, a per-package coverage floor, and more tests and CI. No change in behaviour.

---

## v0.5.1

**Date:** 2026-10-31
**Previous release:** v0.5.0

## Summary

`server` with an ephemeral port and TCP starts on Windows.

**Upgrade notes:** none.

## Changes

### Fixed

- `server`: with port 0 and TCP the server could fail with "no port free for UDP and TCP" on Windows, where ephemeral UDP ports can fall in a range reserved for TCP. It now takes the TCP port first.

---

## v0.5.0

**Date:** 2026-10-30
**Previous release:** v0.4.2

## Summary

Remote device management over the KNX network, and KNX Data Secure point
to point with tool access: a tool reads and writes a device's properties
secured with the device's tool key, and go-knx's server is such a device.
Implemented from public descriptions and xknx (MIT), verified for
interoperability with Calimero tools and xknx, not for conformance.

## Added

- `mgmt`: the remote property services (A_PropertyValue_Read, _Write,
  _Response; A_PropertyDescription_Read and _Response;
  A_DeviceDescriptor_Read type 0) and `mgmt.Responder`, the device side:
  connectionless and in one transport connection at a time (T_Connect,
  numbered data with T_ACK, repetitions, T_Disconnect), secured with
  `Security` (the device's tool key): only S-A_Sync and S-A_Data with tool
  access are answered.
- `client.Device`: remote management of one device through the client's
  link (`PropertyRead`, `PropertyElements`, `PropertyWrite`,
  `DescriptorRead`); `client.Connected()` for a transport connection
  (acknowledgements, repetitions, reconnect after the device's idle
  timeout); `client.WithToolKey`, or the tool key in the client's Data
  Secure table, secures it (S-A_Sync, then S-A_Data with tool access).
- `datasecure.Table`, tool side: `SyncRequest`, `OpenSyncResponse`,
  `SealToolRequest`, `OpenToolResponse`, `ToolKey`; device side
  `RespondTPCI` (the S-A_Sync_Res numbered in a transport connection).
- `server`: the server's own device answers remote device management at
  its individual address (the device, router and KNXnet/IP parameter
  objects, with property descriptions); `server.WithToolKey` secures it
  and adds a security object (type 17, security mode on). The friendly
  name is writable, locally (M_PropWrite) and remotely.
- `interop/node`: container contract 1.4 (`remote-property`, `server
  --tool-access`).

## Changes

- Tool access is authenticated by the tool key alone: any tool that has
  it may synchronise with a device, and tool access sequence numbers are
  kept per peer apart from the group senders (before, an S-A_Sync_Req from
  a sender missing from the table was refused).
- The interop suite pins knx-interop v0.6.0 (contract 1.4).

## Interoperability

knx-interop v0.6.0 matrix with go-knx's node: 448 pass, 7 known
differences, 0 fail.

- Calimero tools 3.0-M1 → go-knx's device: property read (connectionless
  and in a connection), write, description, device information, plain and
  with tool access; plain access to the secured device is refused.
- xknx 4.0.0 → go-knx's device: read and write in a transport connection.
- go-knx → Calimero server 3.0-M1's device: read (connectionless and in a
  connection) and write. Calimero server has no tool key access, so the
  secured tool side of go-knx is verified against go-knx only.
- Calimero tools computes the Data Secure MAC over the source address it
  sends (0.0.0 unless given its address with `-k`), which a tunnelling
  server replaces; go-knx sets the tunnel address.

---

## v0.4.2

**Date:** 2026-10-30
**Previous release:** v0.4.1

## Changes

- go-knx now owns its interop adapter: `interop/node` implements the
  knx-interop container contract 1.3 on the library itself (server and
  client roles, KNX IP Secure, Data Secure, the surrogate role, secure
  routing). knx-interop v0.5.0 tests third-party stacks only and takes a
  system under test as an external adapter.
- `make interop-matrix` runs the knx-interop v0.5.0 matrix with go-knx's
  node as an external adapter (gate: go-knx); the Interop workflow runs it
  and publishes the report.
- The interop suite pins knx-interop v0.5.0.

---

## v0.4.1

**Date:** 2026-10-30
**Previous release:** v0.4.0

## Changes

- The interop suite pins knx-interop v0.4.0 (container contract 1.3: secure
  sessions over UDP, the servers' secure routing, Calimero tools' Data
  Secure through go-knx as the surrogate; full matrix 423 pass, 0 fail).
- server: with listen port 0 and TCP on, the server now finds a port free
  for both UDP and TCP; before, TCP was disabled (with a warning) when the
  ephemeral UDP port was taken for TCP.
- README badges as in the sibling libraries.

---

## v0.4.0

**Date:** 2026-10-30
**Previous release:** v0.3.1

## Summary

The KNX Secure gaps of v0.3.0 closed: S-A_Sync and the surrogate role,
so that Calimero tools can send Data Secure telegrams to go-knx; secure
sessions over UDP; secure routing in the server.

## Added

- `datasecure`: S-A_Sync request and response (`SyncRequest`,
  `OpenSyncRequest`, `SyncResponse`, `OpenSyncResponse`), verified against
  the Application Layer Annex C examples (as reproduced by xknx's open
  work) and a Calimero capture; tool keys in the table (`SetToolKey`,
  `Respond`, `OpenTool`, `SealTool`); `keyring.DataSecure` loads the
  devices' tool keys.
- `client`: with Data Secure, the client answers S-A_Sync and group object
  diagnostics addressed to it as the surrogate of a secured group: it
  sends the group telegram for the tool and delivers it to its own
  subscribers too.
- `tunnel.WithUDP`: KNX IP Secure sessions over UDP; `server.WithSecure`
  serves them (sessions bound to the client's address, idle sessions end).
- `server.WithSecureRouting`: the server's routing with the backbone key
  (timer synchronisation, plain routing frames dropped, Security in the
  secured services DIB).
- `apdu`: A_FunctionPropertyExt_Command/_StateRead/_StateResponse.

## Interoperability

Verified by hand: Calimero tools → go-knx Data Secure through the
surrogate over secure routing; secure sessions over UDP with Calimero
tools and Calimero server (also device management); the server's secure
routing with xknx and Calimero tools. Automated in knx-interop's next
contract version.

---

## v0.3.1

**Date:** 2026-10-30
**Previous release:** v0.3.0

## Changes

- The interop suite pins knx-interop v0.3.0 (container contract 1.2) and
  tests KNX Secure with its public test profile: xknx and Calimero tools
  open secure sessions to go-knx's secure server (bound user addresses,
  write, read, Data Secure decrypted with the profile key, device
  management as user 1), and go-knx's secure client works against
  Calimero's secure server (write seen and Data Secure decrypted by xknx,
  device management, plain connection refused). No library changes.

---

## v0.3.0

**Date:** 2026-10-30
**Previous release:** v0.2.1

## Summary

KNX IP Secure and KNX Data Secure, implemented from public sources (xknx's
MIT implementation and the KNX keyring article; the application notes
were not available) and verified for interoperability with xknx 4.0.0 and
Calimero 3.0-M1. This is not a claim of conformance or certification.

## Added

- `secure`: key derivations, AES-CCM sealing of SECURE_WRAPPER, session
  handshake (X25519, SESSION_RESPONSE and SESSION_AUTHENTICATE MACs),
  sessions with replay protection, TIMER_NOTIFY and the secure routing
  timer (time keeper and follower).
- `tunnel.WithSecure`: secure tunnelling over TCP, with keep alive and
  verification of the server's device authentication code.
- `server.WithSecure`: a secure KNXnet/IP server — secure sessions, users
  bound to tunnelling addresses, device management for user 1, plain
  connections refused, Security family and secured services DIB.
- `routing.WithSecure`: secure routing with the backbone key.
- `datasecure`: S-A_Data for group communication and the security tables;
  `client.WithDataSecure` and `Telegram.Secure`.
- `keyring`: ETS keyrings — signature check, decryption, lookups,
  credentials, Data Secure tables, writing test keyrings.

## Not included

- Data Secure S-A_Sync and point to point security; secure sessions over
  UDP; secure routing in the server.

## Interoperability

Verified by hand (INTEROPERABILITY.md): secure tunnelling with xknx and
Calimero tools as clients and Calimero server as server, secure device
management with Calimero, secure routing both ways with xknx and
Calimero tools, Data Secure both ways with xknx and from go-knx to
Calimero tools. Calimero tools cannot yet send Data Secure telegrams to
go-knx (they need S-A_Sync).

---

## v0.2.1

**Date:** 2026-10-29
**Previous release:** v0.2.0

## Changes

- The interop suite pins knx-interop v0.2.0 (container contract 1.1) and
  tests more of the server against independent clients: xknx and Calimero
  tools over TCP (write, read), Calimero tools' device management (serial
  number) and busmonitor (a telegram of the server, decoded from the TP1
  frame). No library changes.

---

## v0.2.0

**Date:** 2026-10-29
**Previous release:** v0.1.1

## Summary

KNXnet/IP over TCP, tunnelling feature services, device management and
busmonitor, in the client and in the server.

## Additions

- **TCP** (KNXnet/IP core v2): `tunnel.WithTCP()`; the server accepts TCP
  on its port (`server.WithTCP`, default on) and announces core v2 and
  tunnelling v2. No TUNNELLING_ACKs over TCP; connections end with their
  TCP connection.
- **Tunnelling feature services** (v2): `Conn.FeatureGet`,
  `Conn.FeatureSet`; the server answers supported and active EMI type,
  device descriptor, bus connection status, manufacturer code, individual
  address, maximum APDU length and the info service switch.
- **Device management**: package `devmgmt` (`PropRead`, `PropElements`,
  `PropWrite`, `PropertyError`), `tunnel.WithDeviceManagement`; the server
  answers M_PropRead.req for its device, router and KNXnet/IP parameter
  objects, including the interface object list tools address objects by.
- **Busmonitor**: `tunnel.WithLayer(knxnetip.TunnelBusmonitor)` receives
  L_Busmon.ind; `cemi.TP1Frame` and `cemi.ParseTP1` (fuzzed) encode and
  decode TP1 standard frames with the check octet. The server sends
  L_Busmon.ind to busmonitor connections; busmonitor and link layer
  tunnelling exclude each other unless `server.WithConcurrentBusmonitor`.

## Fixes

- **Search request parameter types** of SEARCH_REQUEST_EXTENDED were one
  too high (`knxnetip.SRPProgrammingMode` was 0x02 and so on). They are now
  0x00 invalid, 0x01 programming mode, 0x02 MAC address, 0x03 service,
  0x04 request DIBs, as Calimero and xknx define them. Found because xknx's
  describe, once the server announced core v2, sends an extended search
  with "request DIBs" (0x04), which the server took for "select by
  service" and did not answer.
- Feature frames of the server consume the client's receive sequence
  number (found with the new feature services).

## Verification

go-knx's interop suite against knx-interop v0.1.0 images: TCP tunnel and
feature services, device management (UDP, TCP) against calimero-server
3.0-M1; busmonitor against knxd 0.14.73 (TP1 frames and check octets of
knxd decoded). By hand: Calimero tools over TCP, `get --local` and
`monitor` against the go-knx server.

---

## v0.1.1

**Date:** 2026-10-29
**Previous release:** v0.1.0

## Changes

- The interop suite pins knx-interop v0.1.0: the xknx and KNXUltimate
  images by digest from GHCR; the Calimero and knxd images (GPL binaries,
  never published) built from the v0.1.0 tag. No library changes.

---

## v0.1.0

**Date:** 2026-10-29
**Previous release:** none

## Summary

The first release: KNX addresses, KNXnet/IP frames, cEMI, TPCI/APCI and
209 datapoint subtypes; discovery; a tunnelling client over UDP with
retransmission, heartbeats, NAT and reconnection; routing; group
communication; and a KNXnet/IP server with virtual devices.
Interoperability verified both ways against Calimero 3.0-M1 and knxd
0.14.73, and against xknx 4.0.0 and KNXUltimate 6.3.1 as clients and
routing peers, in the knx-interop matrix and this repository's interop
suite (amd64 and arm64). Coverage 97.7 %.

Fixes found by the interoperability tests: route back data endpoints for
NAT clients, a default routing source address (routers drop 0.0.0), ACK
status handling, write deadlines on multicast sends, ordering of
disconnect metrics and responses.

## Not included

KNXnet/IP over TCP, tunnelling feature services, device management
connections, busmonitor, KNX IP Secure, KNX Data Secure.

---
