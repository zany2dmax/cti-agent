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
