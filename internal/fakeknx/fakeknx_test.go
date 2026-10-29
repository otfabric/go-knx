// SPDX-License-Identifier: MIT

package fakeknx

import "testing"

func TestRequireMulticast(t *testing.T) {
	RequireMulticast(t)
	t.Log("multicast loopback works")
}
