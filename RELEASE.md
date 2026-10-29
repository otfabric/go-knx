# go-knx Releases

Releases are made with the Release workflow (Actions → Release → bump):
it computes the version, tags it and publishes this file's section of
that version as the release notes. Add the section, headed exactly
`## vX.Y.Z` and closed by a line `---`, before running it.

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
