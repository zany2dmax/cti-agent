package main

import (
	"testing"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// Content decides what triage reads, but only mail the receiving server
// vouched for: a forged From carrying a CVE never reaches a model.
func TestOnlyVouchedMailReachesTriageOnItsContent(t *testing.T) {
	good := graph.Message{From: "x@vendor.example", AuthenticationResults: "compauth=pass reason=100"}
	forged := graph.Message{From: "x@vendor.example", AuthenticationResults: "dmarc=fail"}
	none := graph.Message{From: "x@vendor.example"}
	if !senderVouched(good) {
		t.Error("authenticated mail was refused")
	}
	if senderVouched(forged) || senderVouched(none) {
		t.Error("unauthenticated mail was accepted")
	}
}

// A CVE ID in anyone's mail is not a claim on the cleanup: only mail from a
// feed, a colleague or an authenticated sender is CVE mail the digest owns.
func TestOnlyTrustedOrAuthenticatedMailIsCVEMailTheDigestOwns(t *testing.T) {
	good := graph.Message{From: "x@vendor.example", AuthenticationResults: "compauth=pass"}
	forged := graph.Message{From: "x@vendor.example", AuthenticationResults: "dmarc=fail"}
	cases := []struct {
		name             string
		found            int
		feed, team, want bool
		msg              graph.Message
	}{
		{"unauthenticated stranger", 1, false, false, false, forged},
		{"authenticated sender", 1, false, false, true, good},
		{"trusted feed", 2, true, false, true, forged},
		{"colleague", 1, false, true, true, forged},
		{"no CVE at all", 0, true, true, false, good},
	}
	for _, c := range cases {
		if got := ownsCVEMail(c.found, c.feed, c.team, c.msg); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
