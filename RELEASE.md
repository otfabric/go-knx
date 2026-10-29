# go-knx Releases

Releases are made with the Release workflow (Actions → Release → bump):
it computes the version, tags it and publishes this file's section of
that version as the release notes. Add the section, headed exactly
`## vX.Y.Z` and closed by a line `---`, before running it.

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
