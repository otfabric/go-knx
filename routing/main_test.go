// SPDX-License-Identifier: MIT

package routing_test

import (
	"testing"

	"github.com/otfabric/go-knx/internal/leak"
)

// TestMain fails the package when a test leaves a goroutine behind.
func TestMain(m *testing.M) { leak.VerifyNoLeaks(m) }
