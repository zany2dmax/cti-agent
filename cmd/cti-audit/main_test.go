package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runIn(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("AUDIT_DIR", dir)
	t.Setenv("AUDIT_SYSLOG_ADDR", "")
	t.Setenv("FLEET_ENV", filepath.Join(t.TempDir(), "none"))
	var out, errb strings.Builder
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestWithNothingToDoItSaysSoAndExits2(t *testing.T) {
	for _, args := range [][]string{{}, {"--action", "a", "--prune", "--days", "5"}, {"--prune", "--check"}} {
		code, _, errs := runIn(t, t.TempDir(), args...)
		if code != 2 || !strings.Contains(errs, "say what to do") {
			t.Errorf("%v: code %d, stderr %q", args, code, errs)
		}
	}
}

func TestEmitWritesOneSyslogLine(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := runIn(t, dir, "--action", "owners.add", "--target", "app-1", "--outcome", "success", "--lane", "fleet-owners", "--detail", "added")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	if len(files) != 1 {
		t.Fatalf("files: %v", files)
	}
	b, _ := os.ReadFile(files[0])
	line := strings.TrimSpace(string(b))
	for _, want := range []string{" owners.add ", `lane="fleet-owners"`, `target="app-1"`, `outcome="success"`, "added"} {
		if !strings.Contains(line, want) {
			t.Errorf("line lacks %q: %s", want, line)
		}
	}
	if !strings.HasPrefix(line, "<86>1 ") || strings.Count(line, "\n") != 0 {
		t.Errorf("not one RFC 5424 line: %q", line)
	}
}

func TestEmitNeedsAKnownOutcome(t *testing.T) {
	code, _, errs := runIn(t, t.TempDir(), "--action", "a", "--outcome", "maybe")
	if code != 2 || !strings.Contains(errs, "--outcome must be") {
		t.Fatalf("code %d, %q", code, errs)
	}
}

// A script that audits a step must not fail because the log is unwritable.
func TestEmitIntoAMissingDirectoryStillExitsZero(t *testing.T) {
	code, _, errs := runIn(t, filepath.Join(t.TempDir(), "nope"), "--action", "a", "--outcome", "success")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errs, "cannot write") {
		t.Errorf("the problem should be reported: %q", errs)
	}
}

func TestPruneDeletesOnlyOldAuditFiles(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().UTC().AddDate(0, 0, -200).Format("2006-01-02")
	cur := time.Now().UTC().Format("2006-01-02")
	for _, n := range []string{"audit-" + old + ".log", "audit-" + cur + ".log", "other.log"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if code, out, _ := runIn(t, dir, "--prune", "--days", "120", "--dry-run"); code != 0 || !strings.Contains(out, "would delete 1") {
		t.Fatalf("dry run: %d %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-"+old+".log")); err != nil {
		t.Fatal("dry run deleted")
	}
	if code, out, _ := runIn(t, dir, "--prune", "--days", "120"); code != 0 || !strings.Contains(out, "deleted 1") {
		t.Fatalf("prune: %d %q", code, out)
	}
	for n, want := range map[string]bool{"audit-" + old + ".log": false, "audit-" + cur + ".log": true, "other.log": true} {
		_, err := os.Stat(filepath.Join(dir, n))
		if (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", n, err == nil, want)
		}
	}
	if code, _, errs := runIn(t, dir, "--prune"); code != 2 || !strings.Contains(errs, "--days") {
		t.Errorf("--prune without --days: %d %q", code, errs)
	}
}

func TestCheckReportsAWritableAndAnUnwritableTrail(t *testing.T) {
	if code, out, _ := runIn(t, t.TempDir(), "--check"); code != 0 || !strings.Contains(out, "is writable") || !strings.Contains(out, "forwarding is off") {
		t.Fatalf("good dir: %d %q", code, out)
	}
	if code, out, _ := runIn(t, filepath.Join(t.TempDir(), "nope"), "--check"); code != 1 || !strings.Contains(out, "FAIL") {
		t.Fatalf("missing dir: %d %q", code, out)
	}
	if code, out, _ := runIn(t, "off", "--check"); code != 1 || !strings.Contains(out, "discarded") {
		t.Fatalf("off: %d %q", code, out)
	}
}
