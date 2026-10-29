// SPDX-License-Identifier: MIT

// Package knxnetip encodes and decodes KNXnet/IP frames: the header, host
// protocol address information (HPAI), description information blocks
// (DIB), connection request and response information (CRI, CRD) and the
// bodies of the core, device management, tunnelling, routing and secure
// services.
//
// Decoding is strict and never panics: every length field is checked
// against the data, structures of a fixed size must have that size, and
// a frame of an unknown service type decodes to [Unknown] with its body
// kept. Encoding is deterministic: a decoded frame encodes back to the
// same octets.
//
// The cEMI frames that tunnelling, routing and device management carry are
// kept as octets here; package cemi decodes them.
package knxnetip
