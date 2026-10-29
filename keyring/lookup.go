// SPDX-License-Identifier: MIT

package keyring

import "github.com/otfabric/go-knx"

// Interface returns the interface with the individual address, or nil.
func (k *Keyring) Interface(a knx.IndividualAddress) *Interface {
	for i := range k.Interfaces {
		if k.Interfaces[i].IndividualAddress == a {
			return &k.Interfaces[i]
		}
	}
	return nil
}

// Tunnels returns the tunnelling interfaces of a host device.
func (k *Keyring) Tunnels(host knx.IndividualAddress) []Interface {
	var out []Interface
	for _, itf := range k.Interfaces {
		if itf.Type == Tunneling && itf.HasHost && itf.Host == host {
			out = append(out, itf)
		}
	}
	return out
}

// Device returns the device with the individual address, or nil.
func (k *Keyring) Device(a knx.IndividualAddress) *Device {
	for i := range k.Devices {
		if k.Devices[i].IndividualAddress == a {
			return &k.Devices[i]
		}
	}
	return nil
}

// Senders returns every Data Secure sender of the keyring with its last
// known sequence number: the senders listed by the interfaces (0), and
// the devices (their sequence numbers).
func (k *Keyring) Senders() map[knx.IndividualAddress]uint64 {
	out := map[knx.IndividualAddress]uint64{}
	for _, itf := range k.Interfaces {
		for _, senders := range itf.Groups {
			for _, s := range senders {
				out[s] = 0
			}
		}
	}
	for _, d := range k.Devices {
		out[d.IndividualAddress] = d.SequenceNumber
	}
	return out
}
