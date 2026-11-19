package jira

import "os"

// The tests exercise commands that write audit events. They must not write to
// the real trail or print every event; tests that check the events install
// their own logger (audit.SetDefault).
func init() { _ = os.Setenv("AUDIT_DIR", "off") }
