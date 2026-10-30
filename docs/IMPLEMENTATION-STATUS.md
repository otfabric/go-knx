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
| 4 Interoperability expansion | done | knx-interop matrix, 4 independent stacks + probe, JSON/Markdown reports |
| 5 Routing and advanced DPT | done for plain routing | routing between go-knx, xknx, KNXUltimate, Calimero tools and knxd, all directions; DPT matrix of 12 vectors across every implementation |
| 5b TCP, feature services, device management, busmonitor | done (v0.2.0) | see Features; go-knx server ↔ xknx and Calimero tools over TCP, Calimero tools property read and busmonitor (interop/, v0.2.1) |
| 6 Security (KNX IP Secure, KNX Data Secure) | done from public sources (v0.3.0) | AN159/AN158 example vectors (via xknx's tests), keyring files exported by ETS (xknx's fixtures), go-knx ↔ xknx and Calimero by hand (INTEROPERABILITY.md); automated with knx-interop contract 1.2 |
| 7 Release readiness | released | go-knx v0.3.1, knxctl v0.3.0, knx-interop v0.3.0 |

## Features

| Feature | Package | Implementation | Tests | Interoperability |
|---|---|---|---|---|
| Addresses (individual, group 3/2-level/free) | knx | complete | 100 %, fuzzed | — |
| KNXnet/IP frames (core, device management, tunnelling, routing, secure bodies) | knxnetip | complete | 100 %, 45 golden frames, fuzzed | decoded every peer's frames |
| cEMI (L_Data, L_Busmon, L_Raw, M_Prop*, M_FuncProp*, M_Reset) | cemi | complete | 100 %, fuzzed | L_Data exchanged with every peer |
| TPCI/APCI | apdu | complete (all services named; group values decoded) | 100 %, fuzzed | — |
| Datapoint types (209 subtypes) | dpt | complete for the listed families | 99 %, exhaustive DPT 9, xknx vectors | 12 vectors × every implementation |
| Discovery: search, extended search, description | discovery | complete | 92 % | Calimero, knxd, go-knx servers; Calimero tools, xknx, KNXUltimate clients find go-knx |
| Tunnelling client (UDP, v1, NAT, reconnect, v2 address request) | tunnel | complete | 96 % | Calimero 3.0-M1, knxd 0.14.73 |
| Tunnelling over TCP (v2), feature services | tunnel, server | complete (client and server) | e2e, unit | go-knx client → Calimero server (connect, feature get, write, read); Calimero tools → go-knx server (write, read, describe over TCP) |
| Routing (indication, busy, lost message) | routing | complete | 97 % | xknx, KNXUltimate, Calimero tools, knxd, both directions |
| Group communication | client | complete | 99 % | as above |
| KNXnet/IP server (discovery, description, tunnelling, routing) | server | complete | 96 % | Calimero tools, xknx, KNXUltimate, knxd clients; probe negative suite all pass |
| Virtual devices (group objects, CRWTUI flags) | device | complete (application layer only) | 99 % | reads answered to every client |
| Device management connection (M_PropRead, M_PropWrite) | devmgmt, server | complete; server properties read only | e2e, unit | go-knx client → Calimero server (UDP, TCP); Calimero tools `get --local` → go-knx server |
| Busmonitor tunnelling | tunnel, cemi, server | complete (standard frames) | e2e, unit, fuzzed TP1 decoder | go-knx client → knxd server (TP1 frame and check octet decoded); Calimero tools `monitor` → go-knx server (frames and FCS decoded) |
| KNX IP Secure: tunnelling sessions (client, server), SECURE_WRAPPER, secure routing with timer synchronisation | secure, tunnel, server, routing | complete over TCP; no secure sessions over UDP; the server's routing stays plain | 96 %, AN159 vectors, xknx handshake vectors, e2e | xknx and Calimero tools → go-knx server; go-knx → Calimero server (tunnel, device management); routing both ways with xknx and Calimero tools (knx-interop secure suite, interop/secure_test.go) |
| KNX Data Secure (group communication) | datasecure, client | S-A_Data (auth+conf, auth only), security tables; no S-A_Sync, no point to point security | 99 %, xknx vectors | both ways with xknx; go-knx → Calimero tools; Calimero → go-knx not working (S-A_Sync) |
| ETS keyring (.knxkeys) | keyring | read (signature, decryption), write test keyrings | 98 %, ETS-exported fixtures | xknx and Calimero load keyrings written by go-knx |
| ETS project import | — | not implemented | — | — |

## Deviations and decisions

| Topic | Decision | Basis |
|---|---|---|
| NAT clients | A client that sends route back HPAIs gets the route back data endpoint 0.0.0.0:0 in CONNECT_RESPONSE | Behind NAT the server's own address is unreachable; found with Calimero tools and xknx through Docker port mappings |
| Routing source 0.0.0 | Replaced by 15.15.255 (`routing.WithIndividualAddress`) | knxd drops telegrams from 0.0.0 |
| DPT 9 rounding ties | half away from zero (xknx: half to even) | no rule found in the public sources; vectors avoid ties |
| DPT 9 maximum | 670 433.28 (0x7FFF is "invalid data") | the format; matches xknx |
| DPT 17/18 scene numbers | raw 0..63 (xknx presents 1..64) | the encoding |
| Tunnelling v2 status codes 0x2D, 0x2E | used for the extended CRI | cross-checked with xknx's code list |
| Standard frames | NPDU ≤ 15 octets enforced on encode and decode | frame format |
| Data Secure CTR stream | The 4-octet MAC is encrypted first and the APDU continues the same key stream | xknx; checked against its vectors and both ways with xknx, decrypted by Calimero |
| Plain connection to a secure server | refused with E_CONNECTION_TYPE | Calimero's secure server answers the same |
| Secure device management | user 1 (management user) only | Calimero's secure server refuses other users |
| Secure routing timer | starts at 0 when the process starts; adopts any newer timer | the synchronisation of xknx's reading of 3/8/9 §2.2.2.3; Calimero and xknx synchronise with it |
| Wrapper serial number of a secure tunnelling client | 00FA followed by 4 random octets | not checked by xknx or Calimero; the server uses its own serial |

## Known issues found in other implementations

Recorded in knx-interop `tests/known-differences.tsv` and reported upstream
on 2026-10-29:

- KNXUltimate 6.3.1 announces port 3671 in its DESCRIPTION_REQUEST HPAI
  while listening on an ephemeral port; describe fails against every server
  ([KNXUltimate#117](https://github.com/Supergiovane/KNXUltimate/issues/117)).
- calimero-tools 3.0-M1 `describe --json --nat` throws a
  NullPointerException ([calimero-tools#24](https://github.com/calimero-project/calimero-tools/issues/24)).
- knxd 0.14.73's tunnel client never sends its DISCONNECT_REQUEST, leaving
  dead connections on servers ([knxd#667](https://github.com/knxd/knxd/issues/667)).
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

1. Data Secure S-A_Sync (answer and ask for sequence numbers), so that
   Calimero tools can send secured group telegrams to go-knx.
2. Secure routing in the server (`server.WithRouting` with a backbone key)
   and secure sessions over UDP.
