package main

import "os"

// These tests read mail from lists of sender domains (FLEET_UNAUTHENTICATED_SENDERS)
// and so write audit events. They must not write to the real trail, forward to a
// configured collector, or print every event; a test that checks the events
// installs its own logger (audit.SetDefault).
func init() {
	_ = os.Setenv("AUDIT_DIR", "off")
	// AUDIT_DIR=off is refused inside a systemd unit (INVOCATION_ID set); a test
	// run from a unit or a CI service must still not write to the real trail.
	_ = os.Unsetenv("INVOCATION_ID")
}
