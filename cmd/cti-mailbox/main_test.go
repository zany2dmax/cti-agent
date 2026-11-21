package main

import (
	"testing"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// The auto-reply markers are only believed from a sender the receiving server
// authenticated, or internal mail.
func TestSenderUnverifiedFollowsTheReceivingServersVerdict(t *testing.T) {
	good := graph.Message{From: "oof@vendor.example", AuthenticationResults: "compauth=pass"}
	bad := graph.Message{From: "oof@vendor.example", AuthenticationResults: "dmarc=fail"}
	none := graph.Message{From: "oof@vendor.example"}
	if senderUnverified(good) {
		t.Error("an authenticated sender was called unverified")
	}
	if !senderUnverified(bad) || !senderUnverified(none) {
		t.Error("an unauthenticated sender was called verified")
	}
}
