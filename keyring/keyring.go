// SPDX-License-Identifier: MIT

// Package keyring reads and writes KNX keyring files (.knxkeys, namespace
// http://knx.org/xml/keyring/1), the export of the secure keys and
// passwords of an ETS project: the backbone key of secure routing, the
// users and passwords of secure tunnelling, the group keys and senders of
// Data Secure, and the device keys.
//
// The format follows the KNX keyring support article and xknx's reader
// (see docs/standards/SPECIFICATIONS.md, "KNX Secure sources"). Values
// are decrypted on load; the signature is verified first.
package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/pbkdf2"
)

// Namespace is the XML namespace of keyring files.
const Namespace = "http://knx.org/xml/keyring/1"

// Key is an AES-128 key.
type Key [16]byte

// Keyring is a decrypted keyring.
type Keyring struct {
	Project   string
	CreatedBy string
	// Created is the creation time as written in the file; it seeds the
	// encryption of the values.
	Created string

	// Backbone is the secure routing backbone, nil when absent.
	Backbone   *Backbone
	Interfaces []Interface
	// GroupKeys are the Data Secure keys of the group addresses.
	GroupKeys map[knx.GroupAddress]Key
	Devices   []Device
}

// Backbone is the secure routing (multicast) backbone.
type Backbone struct {
	MulticastAddress string
	Latency          time.Duration
	Key              Key
}

// InterfaceType is the type of an interface.
type InterfaceType string

// Interface types.
const (
	Tunneling InterfaceType = "Tunneling"
	USB       InterfaceType = "USB"
	// BackboneInterface is an IP router's backbone interface.
	BackboneInterface InterfaceType = "Backbone"
)

// Interface is a tunnelling address (one user of a secure interface) or
// another interface.
type Interface struct {
	Type              InterfaceType
	IndividualAddress knx.IndividualAddress
	// Host is the individual address of the device providing the
	// interface; HasHost reports whether the file gives one.
	Host    knx.IndividualAddress
	HasHost bool
	// UserID is the secure tunnelling user (0 when none).
	UserID uint8
	// Password is the user's password, Authentication the device
	// authentication password of the host.
	Password       string
	Authentication string
	// Groups are the secured groups the interface receives, each with
	// its allowed senders.
	Groups map[knx.GroupAddress][]knx.IndividualAddress
}

// Device is a secure device.
type Device struct {
	IndividualAddress  knx.IndividualAddress
	ToolKey            Key
	HasToolKey         bool
	ManagementPassword string
	Authentication     string
	// SequenceNumber is the last Data Secure sequence number of the
	// device known to ETS.
	SequenceNumber uint64
}

// ErrSignature reports a keyring whose signature does not match: a wrong
// password or a modified file.
var ErrSignature = fmt.Errorf("%w: keyring: signature verification failed (wrong password or modified file)", knx.ErrSecurity)

// Bounds of a keyring document. ETS keyrings are a few kilobytes and
// a handful of levels deep; the bounds are generous and keep an
// unverified document from consuming unbounded memory or stack.
const (
	maxSize     = 4 << 20 // octets (4 MiB)
	maxDepth    = 64
	maxElements = 1 << 18
)

// maxLatency bounds the backbone latency tolerance, in milliseconds.
const maxLatency = 65535

// LoadFile reads a keyring file of at most 4 MiB.
func LoadFile(path, password string) (*Keyring, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Load(f, password)
}

// Load reads a keyring of at most 4 MiB; a longer input is
// rejected as knx.ErrMalformed without reading further.
func Load(r io.Reader, password string) (*Keyring, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSize {
		return nil, malformed("document larger than %d octets", maxSize)
	}
	return Parse(b, password)
}

// passwordHash derives the keyring key from the keyring password.
func passwordHash(password string) []byte {
	return pbkdf2.SHA256([]byte(password), []byte("1.keyring.ets.knx.org"), 65536, 16)
}

func ivFor(created string) []byte {
	h := sha256.Sum256([]byte(created))
	return h[:16]
}

// Parse decodes and decrypts a keyring. Documents larger than 4 MiB,
// nested deeper than 64 levels or with more than 262144 elements are
// rejected as knx.ErrMalformed before the signature is checked.
func Parse(b []byte, password string) (*Keyring, error) {
	if len(b) > maxSize {
		return nil, malformed("document larger than %d octets", maxSize)
	}
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
	root, err := parseTree(b)
	if err != nil {
		return nil, err
	}
	hash := passwordHash(password)
	if root.name != "Keyring" {
		return nil, malformed("root element %q", root.name)
	}
	sig, err := base64.StdEncoding.DecodeString(root.attr("Signature"))
	if err != nil {
		return nil, malformed("signature: %v", err)
	}
	want, err := signature(root, hash)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return nil, ErrSignature
	}
	d := decrypter{hash: hash, iv: ivFor(root.attr("Created"))}
	k := &Keyring{Project: root.attr("Project"), CreatedBy: root.attr("CreatedBy"), Created: root.attr("Created"), GroupKeys: map[knx.GroupAddress]Key{}}
	for _, e := range root.children {
		switch e.name {
		case "Backbone":
			bb := &Backbone{MulticastAddress: e.attr("MulticastAddress")}
			if v := e.attr("Latency"); v != "" {
				ms, err := strconv.ParseUint(v, 10, 64)
				if err != nil || ms > maxLatency {
					return nil, malformed("backbone latency %q", v)
				}
				bb.Latency = time.Duration(ms) * time.Millisecond
			}
			if bb.Key, err = d.key(e.attr("Key")); err != nil {
				return nil, err
			}
			k.Backbone = bb
		case "Interface":
			itf, err := d.iface(e)
			if err != nil {
				return nil, err
			}
			k.Interfaces = append(k.Interfaces, itf)
		case "GroupAddresses":
			for _, g := range e.children {
				if g.name != "Group" {
					continue
				}
				ga, err := groupAddress(g.attr("Address"))
				if err != nil {
					return nil, err
				}
				if g.attr("Key") == "" {
					continue
				}
				if k.GroupKeys[ga], err = d.key(g.attr("Key")); err != nil {
					return nil, err
				}
			}
		case "Devices":
			for _, de := range e.children {
				if de.name != "Device" {
					continue
				}
				dev, err := d.device(de)
				if err != nil {
					return nil, err
				}
				k.Devices = append(k.Devices, dev)
			}
		}
	}
	return k, nil
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: keyring: %s", knx.ErrMalformed, fmt.Sprintf(format, a...))
}

func groupAddress(s string) (knx.GroupAddress, error) {
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return knx.GroupAddress(n), nil
	}
	g, err := knx.ParseGroupAddress(s)
	if err != nil {
		return 0, malformed("group address %q", s)
	}
	return g, nil
}

func individualAddress(s string) (knx.IndividualAddress, error) {
	a, err := knx.ParseIndividualAddress(s)
	if err != nil {
		return 0, malformed("individual address %q", s)
	}
	return a, nil
}

type decrypter struct{ hash, iv []byte }

func (d decrypter) decrypt(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, malformed("encrypted value: %v", err)
	}
	if len(b) == 0 || len(b)%16 != 0 {
		return nil, malformed("encrypted value of %d octets", len(b))
	}
	block, _ := aes.NewCipher(d.hash)
	cipher.NewCBCDecrypter(block, d.iv).CryptBlocks(b, b)
	return b, nil
}

func (d decrypter) key(s string) (Key, error) {
	var k Key
	if s == "" {
		return k, nil
	}
	b, err := d.decrypt(s)
	if err != nil {
		return k, err
	}
	if len(b) != 16 {
		return k, malformed("key of %d octets", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// password decrypts a password: 8 random octets, the UTF-8 password, and
// padding whose octets give its length.
func (d decrypter) password(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	b, err := d.decrypt(s)
	if err != nil {
		return "", err
	}
	n := int(b[len(b)-1])
	if n == 0 || 8+n > len(b) {
		return "", malformed("password padding")
	}
	return string(b[8 : len(b)-n]), nil
}

func (d decrypter) iface(e *element) (Interface, error) {
	var err error
	itf := Interface{Type: InterfaceType(e.attr("Type")), Groups: map[knx.GroupAddress][]knx.IndividualAddress{}}
	if itf.IndividualAddress, err = individualAddress(e.attr("IndividualAddress")); err != nil {
		return itf, err
	}
	if h := e.attr("Host"); h != "" {
		if itf.Host, err = individualAddress(h); err != nil {
			return itf, err
		}
		itf.HasHost = true
	}
	if u := e.attr("UserID"); u != "" {
		id, err := strconv.ParseUint(u, 10, 8)
		if err != nil {
			return itf, malformed("user ID %q", u)
		}
		itf.UserID = uint8(id)
	}
	if itf.Password, err = d.password(e.attr("Password")); err != nil {
		return itf, err
	}
	if itf.Authentication, err = d.password(e.attr("Authentication")); err != nil {
		return itf, err
	}
	for _, g := range e.children {
		if g.name != "Group" {
			continue
		}
		ga, err := groupAddress(g.attr("Address"))
		if err != nil {
			return itf, err
		}
		var senders []knx.IndividualAddress
		for s := range strings.FieldsSeq(g.attr("Senders")) {
			a, err := individualAddress(s)
			if err != nil {
				return itf, err
			}
			senders = append(senders, a)
		}
		itf.Groups[ga] = senders
	}
	return itf, nil
}

func (d decrypter) device(e *element) (Device, error) {
	var err error
	var dev Device
	if dev.IndividualAddress, err = individualAddress(e.attr("IndividualAddress")); err != nil {
		return dev, err
	}
	if tk := e.attr("ToolKey"); tk != "" {
		if dev.ToolKey, err = d.key(tk); err != nil {
			return dev, err
		}
		dev.HasToolKey = true
	}
	if dev.ManagementPassword, err = d.password(e.attr("ManagementPassword")); err != nil {
		return dev, err
	}
	if dev.Authentication, err = d.password(e.attr("Authentication")); err != nil {
		return dev, err
	}
	if s := e.attr("SequenceNumber"); s != "" {
		if dev.SequenceNumber, err = strconv.ParseUint(s, 10, 48); err != nil {
			return dev, malformed("sequence number %q", s)
		}
	}
	return dev, nil
}

// element is a parsed XML element: its qualified name and attributes as
// written, and its child elements.
type element struct {
	name     string
	attrs    []xml.Attr
	children []*element
}

func (e *element) attr(name string) string {
	for _, a := range e.attrs {
		if qname(a.Name) == name {
			return a.Value
		}
	}
	return ""
}

func qname(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

// parseTree builds the element tree of a document of at most maxDepth
// levels and maxElements elements. Duplicate attributes and end
// elements that do not match their start element are rejected.
func parseTree(b []byte) (*element, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	var stack []*element
	var root *element
	count := 0
	for {
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, malformed("XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxDepth {
				return nil, malformed("elements nested deeper than %d", maxDepth)
			}
			if count++; count > maxElements {
				return nil, malformed("more than %d elements", maxElements)
			}
			e := &element{name: qname(t.Name), attrs: append([]xml.Attr(nil), t.Attr...)}
			if err := uniqueAttrs(e); err != nil {
				return nil, err
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, e)
			} else if root == nil {
				root = e
			} else {
				return nil, malformed("second root element %q", e.name)
			}
			stack = append(stack, e)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, malformed("unbalanced end element")
			}
			if n := qname(t.Name); n != stack[len(stack)-1].name {
				return nil, malformed("end element %q does not match %q", n, stack[len(stack)-1].name)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, malformed("incomplete document")
	}
	return root, nil
}

// uniqueAttrs rejects an element that repeats an attribute.
func uniqueAttrs(e *element) error {
	if len(e.attrs) < 2 {
		return nil
	}
	seen := make(map[string]struct{}, len(e.attrs))
	for _, a := range e.attrs {
		n := qname(a.Name)
		if _, ok := seen[n]; ok {
			return malformed("duplicate attribute %q in %q", n, e.name)
		}
		seen[n] = struct{}{}
	}
	return nil
}

// signature is the first 16 octets of the SHA-256 hash of the document's
// canonical form: per element 0x01, its name and its attributes sorted
// by name (without xmlns and Signature), each string preceded by its
// length; 0x02 at the end of each element; finally the base64 keyring
// key. The recursion is bounded by maxDepth, enforced by parseTree.
func signature(root *element, hash []byte) ([]byte, error) {
	var b []byte
	add := func(s string) error {
		n := len(s)
		if n > 255 {
			return malformed("value of %d octets in the signature", n)
		}
		b = append(append(b, byte(n)), s...)
		return nil
	}
	var walk func(e *element) error
	walk = func(e *element) error {
		b = append(b, 1)
		if err := add(e.name); err != nil {
			return err
		}
		attrs := append([]xml.Attr(nil), e.attrs...)
		sort.Slice(attrs, func(i, j int) bool { return qname(attrs[i].Name) < qname(attrs[j].Name) })
		for _, a := range attrs {
			n := qname(a.Name)
			if n == "xmlns" || n == "Signature" {
				continue
			}
			if err := add(n); err != nil {
				return err
			}
			if err := add(a.Value); err != nil {
				return err
			}
		}
		for _, c := range e.children {
			if err := walk(c); err != nil {
				return err
			}
		}
		b = append(b, 2)
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	if err := add(base64.StdEncoding.EncodeToString(hash)); err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:16], nil
}
