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

// The security team is told it can mail a CVE in to be checked. A colleague
// counts when Exchange took the mail as internal, or authenticated the From
// domain; the From address alone does not, and nobody outside the list does.
func TestATeamSourceIsAnAuthenticatedColleague(t *testing.T) {
	team := []string{"@corp.example"}
	internalNoDMARC := "dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=corp.example;"
	for _, c := range []struct {
		name, from, ar, authAs string
		want                   bool
	}{
		{"colleague, internal", "ana@corp.example", internalNoDMARC, "Internal", true},
		{"colleague, dmarc pass", "ana@corp.example", "dmarc=pass action=none header.from=corp.example;compauth=pass", "", true},
		{"colleague address, not internal, no auth", "ana@corp.example", internalNoDMARC, "", false},
		{"colleague address, anonymous", "ana@corp.example", internalNoDMARC, "Anonymous", false},
		{"stranger, internal header", "x@attacker.example", "", "Internal", false},
		{"stranger, authenticated", "x@attacker.example", "dmarc=pass header.from=attacker.example;compauth=pass", "", false},
	} {
		m := graph.Message{From: c.from, AuthenticationResults: c.ar, AuthAs: c.authAs}
		if got := teamSource(m, team); got != c.want {
			t.Errorf("%s: team = %v, want %v", c.name, got, c.want)
		}
	}
	if teamSource(graph.Message{From: "ana@corp.example", AuthAs: "Internal"}, nil) {
		t.Error("an empty team list matched")
	}
	// The gateway switch turns sender authentication off for the feeds; it
	// must not let a forged From of the org's own domain ask.
	t.Setenv(graph.SenderAuthEnv, "off")
	if teamSource(graph.Message{From: "ana@corp.example"}, team) {
		t.Error("FLEET_SENDER_AUTH=off let an unauthenticated colleague address ask")
	}
}
