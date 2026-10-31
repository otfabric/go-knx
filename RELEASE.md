# go-knx Releases

Releases are made with the Release workflow (Actions → Release → bump):
it computes the version, tags it and publishes this file's section of
that version as the release notes. Add the section, headed exactly
`## vX.Y.Z` and closed by a line `---`, before running it.

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
