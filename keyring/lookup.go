// SPDX-License-Identifier: MIT

package keyring

import (
	"fmt"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/secure"
)

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

// Credentials returns the secure tunnelling credentials of a tunnelling
// interface: its user and password, and the host's device authentication
// password when the keyring has it.
func (i *Interface) Credentials() (secure.Credentials, error) {
	if i.UserID == 0 {
		return secure.Credentials{}, fmt.Errorf("%w: keyring: interface %s has no secure tunnelling user", knx.ErrInvalidValue, i.IndividualAddress)
	}
	return secure.NewCredentials(i.UserID, i.Password, i.Authentication)
}

// DataSecure returns the Data Secure tables of the keyring: its group
// keys and senders; seq is the first sending sequence number (0: derived
// from the clock, see datasecure.NewTable).
func (k *Keyring) DataSecure(seq uint64) (*datasecure.Table, error) {
	keys := make(map[knx.GroupAddress]datasecure.Key, len(k.GroupKeys))
	for g, key := range k.GroupKeys {
		keys[g] = datasecure.Key(key)
	}
	t, err := datasecure.NewTable(keys, k.Senders(), seq)
	if err != nil {
		return nil, err
	}
	for _, d := range k.Devices {
		if d.HasToolKey {
			t.SetToolKey(d.IndividualAddress, datasecure.Key(d.ToolKey))
		}
	}
	return t, nil
}

// BackboneKey returns the secure routing backbone key and latency.
func (k *Keyring) BackboneKey() (secure.Key, time.Duration, bool) {
	if k.Backbone == nil {
		return secure.Key{}, 0, false
	}
	return secure.Key(k.Backbone.Key), k.Backbone.Latency, true
}
