// SPDX-License-Identifier: MIT

// Package knx holds the types shared by every part of go-knx: individual
// and group addresses, telegram priorities, the sentinel errors, the
// logging and metrics interfaces and the connection state.
//
// The protocol is layered over the subpackages:
//
//   - knxnetip: KNXnet/IP frames (header, HPAI, DIB, CRI/CRD and every
//     core, tunnelling, routing, device management and secure service),
//   - cemi: the common External Message Interface (L_Data, M_Prop*),
//   - apdu: the transport and application layer of a telegram (TPCI, APCI),
//   - dpt: datapoint types (encoders, decoders, registry),
//   - discovery: KNXnet/IP search and description,
//   - tunnel: the KNXnet/IP tunnelling client,
//   - routing: KNXnet/IP routing over IP multicast,
//   - client: group communication (read, write, response, subscriptions)
//     over a tunnel or routing link,
//   - server: a KNXnet/IP server (discovery, description, tunnelling,
//     routing) with virtual group objects.
//
// KNX is the building automation standard of the KNX Association
// (ISO/IEC 14543-3). go-knx is an independent implementation; it is not
// certified by the KNX Association.
package knx
