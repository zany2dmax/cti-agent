package main

import (
	"testing"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// PrimeSec 10786589: a CVE counts as trusted only when an allowlisted sender
// whom Exchange Online authenticated mentioned it.
func TestATrustedSourceIsAnAuthenticatedFeedSender(t *testing.T) {
	fail := "dmarc=fail action=none header.from=intel.example;compauth=fail reason=000"
	feed := []string{"@intel.example"}
	for _, c := range []struct {
		name, from, ar string
		want           bool
	}{
		{"feed, authenticated", "news@intel.example", "dmarc=pass action=none header.from=intel.example;compauth=pass", true},
		{"feed, spoofed", "news@intel.example", fail, false},
		{"stranger, authenticated", "x@attacker.example", "dmarc=pass header.from=attacker.example;compauth=pass", false},
		{"qualys, authenticated", "noreply@notify.qualys.com", "compauth=pass reason=100", true},
		{"feed, no header", "news@intel.example", "", false},
	} {
		m := graph.Message{From: c.from, AuthenticationResults: c.ar}
		if got := trustedSource(m, feed); got != c.want {
			t.Errorf("%s: trusted = %v, want %v", c.name, got, c.want)
		}
	}
}
