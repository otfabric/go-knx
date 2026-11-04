// SPDX-License-Identifier: MIT

package discovery

import "net/netip"

// SearchTo sends a (not directed) search to to instead of the multicast
// group, so that a test peer can flood it with answers.
func SearchTo(to netip.AddrPort) Option {
	return func(o *options) error { o.searchTo = to; return nil }
}
