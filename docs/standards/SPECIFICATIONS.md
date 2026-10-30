# KNX specification inventory

This document maps what go-knx implements to the parts of the KNX standard
that define it, and states which sources the implementation was written
from. No specification text is reproduced in this repository.

Research date: 2026-10-29. Licensing and access: [LICENSING.md](LICENSING.md).
Conformance claims: [CONFORMANCE.md](CONFORMANCE.md).

## The layers, kept apart

| Layer | What it is | In go-knx |
|---|---|---|
| **KNX** | The building automation standard of the KNX Association (ISO/IEC 14543-3, EN 50090). Covers media, data link, network, transport and application layers, management, datapoint types and tools | The library implements the parts below; it is not KNX itself |
| **KNXnet/IP** | The IP transport and service family (core, device management, tunnelling, routing, remote diagnosis, security). KNX volume 3 part 8; ISO 22510:2019 | `knxnetip` (frames), `discovery`, `tunnel`, `routing`, `server` |
| **cEMI** | The common External Message Interface: the frame format between an application and a KNX data link layer, used inside KNXnet/IP tunnelling, routing and device management. KNX volume 3 part 6 part 3 (EMI/IMI) | `cemi` |
| **Transport and application layer** | TPCI (transport control) and APCI (application services: group values, memory, properties, management). KNX volume 3 parts 3.4 and 3.7 | `apdu` |
| **Datapoint types (DPT)** | Standardised encodings and semantics of application values. KNX volume 3 part 7 part 2 | `dpt` |
| **KNX TP / PL / RF** | Physical and data link media: twisted pair (TP1), power line (PL110), radio (RF 868 MHz) | Not implemented: go-knx reaches TP/RF only through a KNXnet/IP interface or router. The cEMI frames carry the medium's addressing unchanged |
| **KNX IP Secure** | Authenticated and encrypted KNXnet/IP: secure sessions (tunnelling over TCP), secure routing (multicast with timer synchronisation), SECURE_WRAPPER. KNX volume 3 part 8 part 9; Application Note 159 | Implemented from public sources: `secure`, secure sessions in `tunnel` and `server` (TCP), secure routing in `routing` (see "KNX Secure sources") |
| **KNX Data Secure** | End-to-end security of the application layer (A_SecureService, S-APDU, CCM with group/device keys), independent of the transport. Application Note 158; KNX volume 3 part 3 part 7 (security) | S-A_Data for group communication in `datasecure` and `client` (no S-A_Sync, no point to point); keyrings in `keyring` |
| **KNX IoT** | A separate protocol family (CoAP-based Point API, 3rd Party API), part of KNX Standard v3.0, volume 3 part 10 | Not implemented; out of scope |
| **ETS project formats** | The XML schemas of ETS project (`.knxproj`, namespace `http://knx.org/xml/project/NN`) and keyring (`.knxkeys`, namespace `http://knx.org/xml/keyring/1`) files | Not implemented |

## Feature to specification map

| go-knx feature | Package | Specification (KNX Standard v3.0 numbering) | Notes |
|---|---|---|---|
| Individual and group addresses, presentations | `knx` | 3/3/2 Data link layer general; 3/5/1 resources | Two- and three-level presentation is an installation convention; the 16-bit value is what is sent |
| KNXnet/IP header, HPAI, DIB, CRI/CRD, status codes | `knxnetip` | 3/8/2 Core | Header 0x06/0x10, service identifiers, structures, E_* codes |
| Search, extended search, description | `knxnetip`, `discovery`, `server` | 3/8/2 Core (core v2 adds SEARCH_REQUEST_EXTENDED and search parameters) | |
| Device management frames | `knxnetip` | 3/8/3 Device Management | Frames only; no device management connection |
| Tunnelling (connect, ACK, sequence counters, heartbeat, disconnect) | `tunnel`, `server` | 3/8/4 Tunnelling; 3/8/2 Core (connection management) | UDP, link layer. Tunnelling v2 extended CRI accepted. TCP and feature services: frames only |
| Routing (indication, lost message, busy) | `routing`, `server` | 3/8/5 Routing | Multicast 224.0.23.12:3671 |
| SECURE_WRAPPER, SESSION_*, TIMER_NOTIFY frames | `knxnetip`, `secure` | 3/8/9 KNXnet/IP Secure; AN159 | Encoded, sealed and opened (public sources) |
| cEMI L_Data, L_Busmon, L_Raw, M_Prop*, M_FuncProp*, M_Reset | `cemi` | 3/6/3 EMI/IMI, cEMI clauses | |
| TPCI, APCI, group value services | `apdu` | 3/3/4 Transport layer; 3/3/7 Application layer | |
| Datapoint types 1–29, 232, 242, 251 | `dpt` | 3/7/2 Datapoint Types | Only subtypes with published semantics are registered |

## Sources actually used

The code was written from:

1. The public structure of the KNX standard as documented above (frame
   layouts, field sizes, constants). Section numbers are given for
   orientation; the authors did not have access to the members-only
   v3.0.3/3.0.4 deltas.
2. Behaviour observed on independent implementations in the knx-interop
   matrix (Calimero, knxd, xknx, KNXUltimate). Where the code follows an
   observation rather than a cited clause, the code comment or
   IMPLEMENTATION-STATUS.md says so (for example the status codes 0x2D and
   0x2E of tunnelling v2, confirmed against xknx's list, and the DPT 9
   largest encodable value 670433.28).
3. No source code of another KNX stack was copied. The xknx DPT 20 value
   lists were used to cross-check names and numbers.

## Not yet covered by any source in this repository

- KNX IP Secure and KNX Data Secure are implemented without AN158/AN159
  (see "KNX Secure sources" below and LICENSING.md).
- Tunnelling feature services (TUNNELLING_FEATURE_*) semantics beyond the
  frame layout.
- Device management (local device management with M_PropRead etc. over
  DEVICE_CONFIGURATION_REQUEST).

## KNX Secure sources

KNX IP Secure (3/8/9, AN159) and KNX Data Secure (AN158) are implemented
from public sources only; the application notes themselves were not
available to the project:

| Source | Licence | Used for |
|---|---|---|
| xknx 4.0.0 `xknx/secure`, `xknx/io/ip_secure.py`, `xknx/knxip/` | MIT | CCM construction (CBC-MAC block 0, counter 0), key derivations (PBKDF2 salts and iterations), session handshake MACs, SECURE_WRAPPER and TIMER_NOTIFY layout, routing timer synchronisation, S-A_Data layout, keyring decryption and signature |
| AN159 v06 and AN158 v07 example frames, as cited by xknx's tests | facts quoted in MIT tests | golden vectors in `secure` and `datasecure` |
| KNX keyring support article | public web page | keyring structure and key derivation |
| xknx pull request #1981 (open, MIT) | MIT | S-A_Sync request and response layouts and the Application Layer Annex C worked examples it reproduces |
| bussard (MIT, Rust) pull requests #152/#153 | MIT | confirmation of the S-A_Sync layouts against ETS captures (description only) |
| Calimero 3.0 (GPL) | — | black-box interoperability peer only; its source was not read. The group object diagnostics request of its surrogate service and its surrogate rules were observed on the wire |

The code was written for go-knx, not translated line by line. Where the
behaviour rests on xknx's reading of the specification rather than on a
cited clause (for example the routing timer constants, or the 8 random
octets in front of keyring passwords), the code comment says so. Passing
the interop matrix shows that go-knx and those stacks agree; it does not
show conformance, and no certification is claimed.
