# Implementation status

State of the KNX ecosystem (go-knx, knxctl, knx-interop) on 2026-10-30.
Every "verified" refers to an automated test; interoperability claims name
the implementation versions. Nothing here is a conformance claim
([CONFORMANCE](standards/CONFORMANCE.md)).

## Milestones

| Milestone | Status | Evidence |
|---|---|---|
| 0 Research and architecture | done | [OTFABRIC-CONVENTIONS](architecture/OTFABRIC-CONVENTIONS.md), [SPECIFICATIONS](standards/SPECIFICATIONS.md), [LICENSING](standards/LICENSING.md), knx-interop docs/CANDIDATES.md, ARCHITECTURE.md |
| 1 Protocol foundation (addresses, frames, cEMI, discovery, description) | done | unit/golden/fuzz tests (root, knxnetip, cemi, apdu 100 % coverage); discovery against Calimero, knxd and go-knx servers |
| 2 Working client (tunnelling, group communication, DPT, CLI) | done | go-knx client → Calimero server and knxd: connect, confirmed write, read, inbound telegrams (interop/ and the matrix) |
| 3 Working server | done | Calimero tools, xknx, KNXUltimate and knxd clients → go-knx server: discover, describe, connect, write, read (matrix; interop/ through NAT) |
| 4 Interoperability expansion | done | knx-interop matrix, 5 independent stacks (cB-Sigma knx with knx-sim since knx-interop v0.9.0) + probe, JSON/Markdown reports |
| 5 Routing and advanced DPT | done for plain routing | routing between go-knx, xknx, KNXUltimate, Calimero tools and knxd, all directions; DPT matrix of 12 vectors across every implementation |
| 5b TCP, feature services, device management, busmonitor | done (v0.2.0) | see Features; go-knx server ↔ xknx and Calimero tools over TCP, Calimero tools property read and busmonitor (interop/, v0.2.1) |
| 6 Security (KNX IP Secure, KNX Data Secure) | done from public sources (v0.3.0) | AN159/AN158 example vectors (via xknx's tests), keyring files exported by ETS (xknx's fixtures), go-knx ↔ xknx and Calimero by hand (INTEROPERABILITY.md); automated with knx-interop contract 1.2 |
| 7 Release readiness | released | first: go-knx v0.4.1, knxctl v0.4.0, knx-interop v0.4.0; the interop suite now pins knx-interop v0.9.1 |

## Features

| Feature | Package | Implementation | Tests | Interoperability |
|---|---|---|---|---|
| Addresses (individual, group 3/2-level/free) | knx | complete | 100 %, fuzzed | — |
| KNXnet/IP frames (core, device management, tunnelling, routing, secure bodies) | knxnetip | complete | 100 %, 45 golden frames, fuzzed | decoded every peer's frames |
| cEMI (L_Data, L_Busmon, L_Raw, M_Prop*, M_FuncProp*, M_Reset) | cemi | complete | 100 %, fuzzed | L_Data exchanged with every peer |
| TPCI/APCI | apdu | complete (all services named; group values decoded) | 100 %, fuzzed | — |
| Datapoint types (239 subtypes: main types 1–22, 26, 27, 29, 217, 222, 232, 234, 242, 251, 275) | dpt | complete for the listed families; of the 3/7/2 v2.2 additions: 5.100, 15.000, 20.107, 21.002, 21.100–21.106, 21.601, 21.1000, 21.1001, 21.1010, 21.1200, 21.1201, 22.100, 22.101, 22.103, 22.1000, 22.1010, 27.001, 217.001, 222.100/101, 234.001/002, 275.100/101 (their encodings decode to the same values in xknx 4.1.1). Not registered, as their exact layout is not confirmed from a published source here: 20.116, 21.1002, 22.102, 206.x, 207.x, 219.001, 225.001/002, 229.001, 230.1000, 236.001, 237.600, 238.x, 240.800, 241.800, 244–248.600, 255.001, 272.600, 273.001–007 | 99 %, exhaustive DPT 9, xknx vectors | 12 vectors × every implementation |
| Discovery: search, extended search, description | discovery | complete | 92 % | Calimero, knxd, go-knx servers; Calimero tools, xknx, KNXUltimate clients find go-knx |
| Tunnelling client (UDP, v1, NAT, reconnect, v2 address request) | tunnel | complete | 96 % | Calimero 3.0-M1, knxd 0.14.73; cB-Sigma knx-sim: repeated indication delivered once, unacknowledged request reported, replayed and tampered secure wrappers discarded, session closed by the gateway dropped, idle secure session kept alive past 60 s |
| Tunnelling over TCP (v2), feature services | tunnel, server | complete (client and server) | e2e, unit | go-knx client → Calimero server (connect, feature get, write, read); Calimero tools → go-knx server (write, read, describe over TCP) |
| Routing (indication, busy, lost message) | routing | complete | 97 % | xknx, KNXUltimate, Calimero tools, knxd, cB-Sigma knx, both directions; flow control against cB-Sigma knx-sim's router (ROUTING_BUSY wait honoured, ROUTING_LOST_MESSAGE tolerated) |
| Group communication | client | complete | 99 % | as above |
| KNXnet/IP server (discovery, description, tunnelling, routing) | server | complete | 96 % | Calimero tools, xknx, KNXUltimate, knxd and cB-Sigma knx clients (cB-Sigma also over TCP, busmonitor, KNX IP Secure and Data Secure); probe negative suite all pass |
| Virtual devices (group objects, CRWTUI flags) | device | complete (application layer only) | 99 % | reads answered to every client |
| Device management connection (M_PropRead, M_PropWrite) | devmgmt, server | complete; the server's friendly name is writable, its other properties read only | e2e, unit | go-knx client → Calimero server (UDP, TCP); Calimero tools `get --local` → go-knx server |
| Remote device management (A_PropertyValue_Read/_Write, A_PropertyDescription_Read, A_DeviceDescriptor_Read; transport connections) | mgmt, client, server | tool (`client.Device`, including `PropertyDescription`) and device (`mgmt.Responder`, the server's own device); property datatypes (`mgmt.PDT`) with element sizes; no memory, restart or ADC services | 95 %, e2e | Calimero tools and xknx → go-knx server; go-knx → Calimero server (knx-interop management suite; the tool side of A_PropertyDescription_Read only against go-knx so far) |
| KNX Data Secure point to point, tool access | datasecure, mgmt, client, server | S-A_Sync as tool and as device, S-A_Data with tool access in both directions, connectionless and in transport connections; plain access refused by a secured device; a security object (type 17, PID 51 security mode) | e2e, a Calimero capture | Calimero tools → go-knx server (read, read in a connection, write, description, device info); go-knx's tool side only against go-knx (no third-party device with tool access) |
| Busmonitor tunnelling | tunnel, cemi, server | complete (standard frames) | e2e, unit, fuzzed TP1 decoder | go-knx client → knxd server (TP1 frame and check octet decoded); Calimero tools `monitor` → go-knx server (frames and FCS decoded) |
| KNX IP Secure: tunnelling sessions (client, server), SECURE_WRAPPER, secure routing with timer synchronisation | secure, tunnel, server, routing | complete: sessions over TCP and UDP, secure routing in routing and server | 96 %, AN159 vectors, xknx handshake vectors, e2e | xknx and Calimero tools → go-knx server; go-knx → Calimero server (tunnel, device management); routing both ways with xknx and Calimero tools (knx-interop secure suite, interop/secure_test.go) |
| KNX Data Secure (group communication) | datasecure, client | S-A_Data (auth+conf, auth only), security tables, S-A_Sync, surrogate (group object diagnostics) | 99 %, xknx vectors, Annex C S-A_Sync vectors, a Calimero capture | both ways with xknx; go-knx → Calimero tools; Calimero tools → go-knx through go-knx as surrogate |
| ETS keyring (.knxkeys) | keyring | read (signature, decryption), write test keyrings | 98 %, ETS-exported fixtures | xknx and Calimero load keyrings written by go-knx |
| ETS project import | — | not implemented | — | — |

## Deviations and decisions

| Topic | Decision | Basis |
|---|---|---|
| NAT clients | A client that sends route back HPAIs gets the route back data endpoint 0.0.0.0:0 in CONNECT_RESPONSE | Behind NAT the server's own address is unreachable; found with Calimero tools and xknx through Docker port mappings |
| Routing flow control | ROUTING_BUSY counted when more than 10 ms after the previous one; pause of wait time + random 0 … N × 50 ms; N kept for N × 100 ms after the pause, then decremented every 5 ms; gap × (N + 1) while N > 0; minimum gap 1/rate, no bursts; client and server alike (`internal/flowctl`) | our reading of 3/8/5 §2.3.5 and of the inter-frame gap of 3/2/6 §2.1; the reduced-rate factor and the 20 ms unit at an unlimited rate are our choice; deterministic unit tests, e2e with a peer sending ROUTING_BUSY |
| Routing source 0.0.0 | Replaced by 15.15.255 (`routing.WithIndividualAddress`) | knxd drops telegrams from 0.0.0 |
| DPT 9 rounding ties | half away from zero (xknx: half to even) | no rule found in the public sources; vectors avoid ties |
| DPT 9 maximum | 670 433.28 (0x7FFF is "invalid data") | the format; matches xknx |
| DPT 17/18 scene numbers | raw 0..63 (xknx presents 1..64) | the encoding |
| Tunnelling v2 status codes 0x2D, 0x2E | used for the extended CRI | cross-checked with xknx's code list |
| Standard frames | NPDU ≤ 15 octets enforced on encode and decode | frame format |
| Data Secure CTR stream | The 4-octet MAC is encrypted first and the APDU continues the same key stream | xknx; checked against its vectors and both ways with xknx, decrypted by Calimero |
| Plain connection to a secure server | refused with E_CONNECTION_TYPE | Calimero's secure server answers the same |
| Secure device management | user 1 (management user) only | Calimero's secure server refuses other users |
| Secure routing timer | starts at 0 when the process starts; adopts any newer timer; saturates at 2^48−1 instead of wrapping; message tags and notify delays come from crypto/rand | the synchronisation of xknx's reading of 3/8/9 §2.2.2.3; Calimero and xknx synchronise with it |
| Tool access sequence numbers | kept per peer apart from the group senders; any tool that has the device's tool key may synchronise | the tool key is the tool's credential; Calimero synchronises with sequence 1 and a zero serial number |
| Data Secure MAC of a tunnelling client | computed over the source address the frame carries on the network (the tunnel address); go-knx sets it | Calimero tools 3.0-M1 computes it over 0.0.0 unless given its address (`-k`), and a device then refuses its frames |
| Wrapper serial number of a secure tunnelling client | 00FA followed by 4 random octets | not checked by xknx or Calimero; the server uses its own serial |
| Data Secure surrogate | answers S-A_Sync_Req and group object diagnostics (A_FunctionPropertyExt_Command, object type 9, PID 66) addressed to the client, with its tool key; the first tool frame may reuse the request's sequence number once | Calimero tools send secured group telegrams only through a surrogate device; layout observed from Calimero 3.0-M1 (reserved, command 01 write, mode, group, value), return code 0 and the first two octets echoed |
| Calimero's surrogate choice | every sender of the group (across all keyring interfaces) must be a keyring device with a tool key; Calimero picks one of them | observed; the knx-interop profile gives the surrogate group 1/3/3 a single sender |

## Known issues found in other implementations

Recorded in knx-interop `tests/known-differences.tsv` and reported upstream
(2026-10-29 and 2026-11-06):

- KNXUltimate 6.3.1 announced port 3671 in its DESCRIPTION_REQUEST HPAI
  while listening on an ephemeral port
  ([KNXUltimate#117](https://github.com/Supergiovane/KNXUltimate/issues/117));
  fixed in 6.3.2.
- knxd 0.14.73 and KNXUltimate 6.3.2 do not pause after ROUTING_BUSY
  ([knxd#669](https://github.com/knxd/knxd/issues/669),
  [KNXUltimate#118](https://github.com/Supergiovane/KNXUltimate/issues/118)).
- xknx 4.1.1 and KNXUltimate 6.3.2 cannot report an unacknowledged
  tunnelling write to the application
  ([xknx#2024](https://github.com/XKNX/xknx/issues/2024),
  [KNXUltimate#119](https://github.com/Supergiovane/KNXUltimate/issues/119)).
- Calimero 3.0-M1 ignores a SESSION_STATUS close from the server
  ([calimero-core#181](https://github.com/calimero-project/calimero-core/issues/181)).
- cB-Sigma knx-sim v0.2.0 gives tunnels addresses beyond its announced slots,
  and cB-Sigma knx v0.2.0's plain router pauses on its own ROUTING_BUSY
  ([knx-sim#1](https://github.com/cB-Sigma/knx-sim/issues/1),
  [knx#1](https://github.com/cB-Sigma/knx/issues/1)).
- calimero-tools 3.0-M1 `describe --json --nat` throws a
  NullPointerException ([calimero-tools#24](https://github.com/calimero-project/calimero-tools/issues/24)).
- knxd 0.14.73's tunnel client never sends its DISCONNECT_REQUEST, leaving
  dead connections on servers ([knxd#537](https://github.com/knxd/knxd/issues/537);
  our [knxd#667](https://github.com/knxd/knxd/issues/667) was closed as its duplicate).
- calimero-server 3.0-M1 restarts its control endpoint (about 10 s without
  answers) after a 3-octet datagram or a CRI of length 0: already fixed on
  master (d276d8a8), not reported.

The two unexplained matrix failures of the first runs were traced to the
knxd disconnect bug and to a probe check that ran during calimero-server's
restart; both are fixed in the knx-interop harness.

## Blockers

1. ~~KNX IP Secure and Data Secure sourcing~~: decided 2026-10-30 —
   implemented from public sources and verified against xknx and Calimero
   ([LICENSING](standards/LICENSING.md)). Conformance to AN158/AN159 is not
   established.
2. ~~Publishing GPL-carrying interop images~~: decided — they are built
   when needed and never published.
3. Hardware validation (a physical KNX IP interface or router) is not
   possible here.

## Next steps

1. Point to point Data Secure between devices (link keys) and secure
   commissioning with the FDSK.
