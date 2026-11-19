package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// --check reports the owner lane as the lane decides it. With owners.db
// keeping the allowed domains, an unset OWNER_ALLOW_DOMAINS is normal, and
// the old "unset means it will not send" was false - the check-in recorded
// it as fact (trace checkin-20261118T103109).
func TestTheOwnerCheckLineFollowsOwnersDB(t *testing.T) {
	t.Setenv("OWNER_ALLOW_DOMAINS", "")
	o, _, err := appscan.ParseOwnersSnapshot(strings.NewReader(`{"format":"cti-owners/1",
		"apps":[{"app":"id:1","owner":"lead@example.com"}],
		"allowedDomains":["example.com","agency.example"]}`))
	if err != nil {
		t.Fatal(err)
	}
	st, txt := ownerCheckLine(o, "owners.json", nil)
	if strings.TrimSpace(st) != "OK" || !strings.Contains(txt, "armed - 2 allowed domain(s) in the allowed domains in owners.db") {
		t.Errorf("got %q %q", st, txt)
	}

	o, _, err = appscan.ParseOwnersSnapshot(strings.NewReader(`{"format":"cti-owners/1",
		"apps":[{"app":"id:1","owner":"lead@example.com"}],"allowedDomains":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if st, txt := ownerCheckLine(o, "", nil); strings.TrimSpace(st) != "none" || !strings.Contains(txt, "off -") {
		t.Errorf("empty list: got %q %q", st, txt)
	}
}

func TestTheOwnerCheckLineFallsBackToTheVariableWithoutOwnersDB(t *testing.T) {
	t.Setenv("OWNER_ALLOW_DOMAINS", "example.com")
	o, _, err := appscan.ParseOwners(strings.NewReader("id:1 | lead@example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if st, txt := ownerCheckLine(o, "app-owners.txt", nil); strings.TrimSpace(st) != "OK" || !strings.Contains(txt, "in OWNER_ALLOW_DOMAINS") {
		t.Errorf("got %q %q", st, txt)
	}
}

func TestUnreadableOwnersFailTheOwnerLine(t *testing.T) {
	if st, txt := ownerCheckLine(appscan.Owners{}, "", errors.New("permission denied")); strings.TrimSpace(st) != "FAIL" || !strings.Contains(txt, "permission denied") {
		t.Errorf("got %q %q", st, txt)
	}
}
