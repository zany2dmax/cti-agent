package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
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

// The cases below came over from the Python suite's GrantedRoles when
// mailer.py was retired, so the check keeps the coverage it had there.

func TestTheTwoRequiredCapabilitiesPass(t *testing.T) {
	out, rc := check(t, "Mail.Read", "Mail.Send")
	if rc != exitOK {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
	for _, want := range []string{"read the CTI mailbox", "send the digest"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// Mail.ReadWrite includes the read, so a tenant that pruned Mail.Read after
// granting it is correctly configured, not broken.
func TestReadWriteSatisfiesTheReadRequirement(t *testing.T) {
	out, rc := check(t, "Mail.ReadWrite", "Mail.Send")
	if rc != exitOK || strings.Contains(out, "MISSING") {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
}

func TestAMissingSendRoleFails(t *testing.T) {
	out, rc := check(t, "Mail.Read")
	if rc == exitOK || !strings.Contains(out, "MISSING  Mail.Send") {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
}

// The cleanup lane is opt-in, so its permission can never fail the check.
func TestCleanupRoleIsReportedButNeverFatal(t *testing.T) {
	out, rc := check(t, "Mail.Read", "Mail.Send")
	if rc != exitOK || !strings.Contains(out, "absent   Mail.ReadWrite - move mail - cti-mailbox cleanup") {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
	out, rc = check(t, "Mail.ReadWrite", "Mail.Send")
	if rc != exitOK || !strings.Contains(out, "OK       Mail.ReadWrite   move mail - cti-mailbox cleanup") {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
}

// The finding from the real app registration: directory, user and audit-log
// roles consented and called by nothing. Named, and not fatal.
func TestUnusedPermissionsAreNamed(t *testing.T) {
	out, rc := check(t, "Mail.Read", "Mail.Send", "Mail.ReadWrite",
		"Directory.Read.All", "User.Read.All", "AuditLog.Read.All")
	if rc != exitOK {
		t.Fatalf("unused roles failed the check: rc = %d", rc)
	}
	var unused string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "UNUSED") {
			unused = l
		}
	}
	for _, r := range []string{"Directory.Read.All", "User.Read.All", "AuditLog.Read.All"} {
		if !strings.Contains(unused, r) {
			t.Errorf("%s not named as unused:\n%s", r, out)
		}
	}
	for _, r := range []string{"Mail.Read,", "Mail.Send", "Mail.ReadWrite"} {
		if strings.Contains(unused, r) {
			t.Errorf("%s called unused: %s", r, unused)
		}
	}
}

func TestAMinimalGrantReportsNothingUnused(t *testing.T) {
	if out, _ := check(t, "Mail.ReadWrite", "Mail.Send"); strings.Contains(out, "UNUSED") {
		t.Fatalf("a minimal grant reported unused roles:\n%s", out)
	}
}

func TestNoRolesAtAllIsReportedNotCrashed(t *testing.T) {
	out, rc := check(t)
	if rc == exitOK || !strings.Contains(out, "(none)") {
		t.Fatalf("rc = %d\n%s", rc, out)
	}
}

// usedRoles is a claim about the codebase: check it against the Graph calls
// the code makes, so a new call needing another permission is not reported
// as an unused role somebody then removes.
func TestTheUsedSetMatchesTheEndpointsTheCodeCalls(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	graph := read("../../internal/graph/client.go")
	for _, ep := range []string{"/mailFolders/%s/messages", "/sendMail", "/messages/%s/move"} {
		if !strings.Contains(graph, ep) {
			t.Errorf("internal/graph no longer calls %s", ep)
		}
	}
	drive := read("../../internal/graph/driveitem.go")
	for _, ep := range []string{`"/drives/"`, "/content"} {
		if !strings.Contains(drive, ep) {
			t.Errorf("internal/graph/driveitem.go no longer calls %s", ep)
		}
	}
	for _, forbidden := range []string{"/auditLogs", "/directoryObjects", "/servicePrincipals"} {
		if strings.Contains(graph, forbidden) {
			t.Errorf("%s needs a permission usedRoles omits", forbidden)
		}
	}
	want := []string{"Files.Read.All", "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Sites.Read.All", "Sites.Selected"}
	var got []string
	for r := range usedRoles {
		got = append(got, r)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("usedRoles = %v, want %v", got, want)
	}
}
