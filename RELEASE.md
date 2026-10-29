# go-knx Releases

Releases are made with the Release workflow (Actions → Release → bump):
it computes the version, tags it and publishes this file's section of
that version as the release notes. Add the section, headed exactly
`## vX.Y.Z` and closed by a line `---`, before running it.

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
