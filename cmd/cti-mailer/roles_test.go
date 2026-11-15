package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// token is an unsigned JWT carrying only the claims reportRoles reads.
func token(t *testing.T, roles ...string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"tid": "tenant", "appid": "app", "roles": roles})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

func check(t *testing.T, roles ...string) (string, int) {
	t.Helper()
	var buf bytes.Buffer
	old := logOut
	logOut = &buf
	defer func() { logOut = old }()
	rc := reportRoles(token(t, roles...), "fleet@example.com")
	return buf.String(), rc
}

func TestSitesSelectedIsUsedNotUnused(t *testing.T) {
	out, rc := check(t, "Mail.ReadWrite", "Mail.Send", "Sites.Selected")
	if rc != exitOK {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
	if !strings.Contains(out, "OK       Sites.Selected   read the network spreadsheet") {
		t.Errorf("Sites.Selected not reported OK:\n%s", out)
	}
	if !strings.Contains(out, "cti-vmscan --check reads the file") {
		t.Errorf("no note that the site grant is not in the token:\n%s", out)
	}
	if strings.Contains(out, "UNUSED") {
		t.Errorf("Sites.Selected called UNUSED:\n%s", out)
	}
}

func TestNoSiteRoleIsAbsentNotFatal(t *testing.T) {
	out, rc := check(t, "Mail.ReadWrite", "Mail.Send", "Directory.Read.All")
	if rc != exitOK {
		t.Fatalf("a missing optional role failed the check: rc = %d", rc)
	}
	if !strings.Contains(out, "absent   Sites.Selected or Files.Read.All or Sites.Read.All - read the network spreadsheet") {
		t.Errorf("a missing site role is not reported:\n%s", out)
	}
	if !strings.Contains(out, "UNUSED   1 role(s) granted that this codebase never calls: Directory.Read.All") {
		t.Errorf("the unused role is not reported:\n%s", out)
	}
}

func TestBroadSiteRolesAreFlagged(t *testing.T) {
	out, _ := check(t, "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Sites.Read.All")
	if !strings.Contains(out, "BROAD    Files.Read.All, Sites.Read.All reach every site") {
		t.Errorf("broad roles not flagged:\n%s", out)
	}
	if strings.Contains(out, "UNUSED") {
		t.Errorf("broad site roles called UNUSED:\n%s", out)
	}
}
