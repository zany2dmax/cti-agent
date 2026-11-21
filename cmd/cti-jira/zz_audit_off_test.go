package main

import "os"

// The tests exercise commands that write audit events. They must not write to
// the real trail or print every event; tests that check the events install
// their own logger (audit.SetDefault).
func init() {
	_ = os.Setenv("AUDIT_DIR", "off")
	// AUDIT_DIR=off is refused inside a systemd unit (INVOCATION_ID set); a test
	// run from a unit or a CI service must still not write to the real trail.
	_ = os.Unsetenv("INVOCATION_ID")
}
