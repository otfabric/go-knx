// SPDX-License-Identifier: MIT

package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-knx"
)

// Encode writes the keyring as a .knxkeys document encrypted and signed
// with password. It is meant for test installations and tools; ETS
// remains the source of keyrings for real projects. An empty Created is
// set to the current time.
func (k *Keyring) Encode(password string) ([]byte, error) {
	return k.encode(password, rand.Reader)
}

func (k *Keyring) encode(password string, rnd io.Reader) ([]byte, error) {
	if k.Created == "" {
		k.Created = time.Now().UTC().Format("2006-01-02T15:04:05")
	}
	hash := passwordHash(password)
	e := encrypter{hash: hash, iv: ivFor(k.Created), rnd: rnd}
	root := &element{name: "Keyring"}
	root.set("Project", k.Project)
	root.set("CreatedBy", k.CreatedBy)
	root.set("Created", k.Created)
	if bb := k.Backbone; bb != nil {
		c := root.child("Backbone")
		c.set("MulticastAddress", bb.MulticastAddress)
		c.set("Latency", strconv.FormatInt(bb.Latency.Milliseconds(), 10))
		c.set("Key", e.key(bb.Key))
	}
	for _, itf := range k.Interfaces {
		c := root.child("Interface")
		c.set("IndividualAddress", itf.IndividualAddress.String())
		c.set("Type", string(itf.Type))
		if itf.HasHost {
			c.set("Host", itf.Host.String())
		}
		if itf.UserID != 0 {
			c.set("UserID", strconv.Itoa(int(itf.UserID)))
		}
		for _, p := range []struct{ name, v string }{{"Password", itf.Password}, {"Authentication", itf.Authentication}} {
			if p.v != "" {
				v, err := e.password(p.v)
				if err != nil {
					return nil, err
				}
				c.set(p.name, v)
			}
		}
		for _, g := range sortedGroups(itf.Groups) {
			gc := c.child("Group")
			gc.set("Address", strconv.Itoa(int(g)))
			var s []string
			for _, a := range itf.Groups[g] {
				s = append(s, a.String())
			}
			gc.set("Senders", strings.Join(s, " "))
		}
	}
	if len(k.GroupKeys) > 0 {
		c := root.child("GroupAddresses")
		for _, g := range sortedGroups(k.GroupKeys) {
			gc := c.child("Group")
			gc.set("Address", strconv.Itoa(int(g)))
			gc.set("Key", e.key(k.GroupKeys[g]))
		}
	}
	if len(k.Devices) > 0 {
		c := root.child("Devices")
		for _, d := range k.Devices {
			dc := c.child("Device")
			dc.set("IndividualAddress", d.IndividualAddress.String())
			if d.HasToolKey {
				dc.set("ToolKey", e.key(d.ToolKey))
			}
			for _, p := range []struct{ name, v string }{{"ManagementPassword", d.ManagementPassword}, {"Authentication", d.Authentication}} {
				if p.v != "" {
					v, err := e.password(p.v)
					if err != nil {
						return nil, err
					}
					dc.set(p.name, v)
				}
			}
			if d.SequenceNumber != 0 {
				dc.set("SequenceNumber", strconv.FormatUint(d.SequenceNumber, 10))
			}
		}
	}
	sig, err := signature(root, hash)
	if err != nil {
		return nil, err
	}
	// Signature and namespace follow the other attributes, as in ETS
	// exports; neither is part of the signature.
	root.set("Signature", base64.StdEncoding.EncodeToString(sig))
	root.set("xmlns", Namespace)
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	root.write(&b, 0)
	return b.Bytes(), nil
}

func sortedGroups[V any](m map[knx.GroupAddress]V) []knx.GroupAddress {
	gs := make([]knx.GroupAddress, 0, len(m))
	for g := range m {
		gs = append(gs, g)
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i] < gs[j] })
	return gs
}

func (e *element) set(name, v string) {
	e.attrs = append(e.attrs, xml.Attr{Name: xml.Name{Local: name}, Value: v})
}

func (e *element) child(name string) *element {
	c := &element{name: name}
	e.children = append(e.children, c)
	return c
}

func (e *element) write(b *bytes.Buffer, depth int) {
	ind := strings.Repeat("  ", depth)
	b.WriteString(ind + "<" + e.name)
	for _, a := range e.attrs {
		b.WriteString(" " + a.Name.Local + `="`)
		_ = xml.EscapeText(b, []byte(a.Value))
		b.WriteString(`"`)
	}
	if len(e.children) == 0 {
		b.WriteString(" />\n")
		return
	}
	b.WriteString(">\n")
	for _, c := range e.children {
		c.write(b, depth+1)
	}
	b.WriteString(ind + "</" + e.name + ">\n")
}

type encrypter struct {
	hash, iv []byte
	rnd      io.Reader
}

func (e encrypter) encrypt(b []byte) string {
	block, _ := aes.NewCipher(e.hash)
	out := make([]byte, len(b))
	cipher.NewCBCEncrypter(block, e.iv).CryptBlocks(out, b)
	return base64.StdEncoding.EncodeToString(out)
}

func (e encrypter) key(k Key) string { return e.encrypt(k[:]) }

func (e encrypter) password(p string) (string, error) {
	b := make([]byte, 8, 8+len(p)+16)
	if _, err := io.ReadFull(e.rnd, b); err != nil {
		return "", fmt.Errorf("keyring: random: %w", err)
	}
	b = append(b, p...)
	n := 16 - len(b)%16
	for i := 0; i < n; i++ {
		b = append(b, byte(n))
	}
	return e.encrypt(b), nil
}
