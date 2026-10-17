package patchtuesday

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDropDirIsPerRelease(t *testing.T) {
	if got := DropDir("/var/lib/cti-agent", 2026, time.November); got != "/var/lib/cti-agent/inbox/patchtuesday/2026-11" {
		t.Errorf("DropDir = %q", got)
	}
}

func TestFindSavedMatchesByNameAndSkipsTheRest(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".qualys.html", "hidden")
	write(t, dir, "qualys-notes.pdf", "wrong type")
	want := write(t, dir, "Microsoft Patch Tuesday - Qualys.html", "<p>x</p>")
	if got := FindSaved(dir, "qualys"); got != want {
		t.Errorf("FindSaved = %q, want %q", got, want)
	}
	if got := FindSaved(dir, "bleeping"); got != "" {
		t.Errorf("found a bleeping file that is not there: %q", got)
	}
	if got := FindSaved(filepath.Join(dir, "missing"), "qualys"); got != "" {
		t.Errorf("a missing folder found %q", got)
	}
}

func TestASavedPageParsesLikeAFetchedOne(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "bleeping.html", bleepingFixture)
	s := LoadSaved(p, "BleepingComputer Patch Tuesday", "https://example.com/article")
	if !s.Fetched || s.URL != "https://example.com/article" || !strings.Contains(s.Name, "saved copy") {
		t.Fatalf("source = %+v", s)
	}
	s.Role = RoleBleeping
	d := &Digest{Year: 2026, Month: time.August, Sources: []Source{s}}
	Parse(d)
	if d.Total != 400 {
		t.Errorf("Total = %d, want 400 from the saved page", d.Total)
	}
}

func TestCopiedTextKeepsItsParagraphs(t *testing.T) {
	// Copy-paste from a browser is plain lines. Run together into one, the
	// zero-day sentence pattern would run across paragraphs.
	dir := t.TempDir()
	p := write(t, dir, "bleeping.txt",
		"Microsoft August 2026 Patch Tuesday fixes 400 flaws, 3 zero-days\r\n"+
			"Today is Microsoft's August 2026 Patch Tuesday, which fixes 400 flaws, including <three> zero-days.\r\n"+
			"Next paragraph.\n")
	s := LoadSaved(p, "BleepingComputer Patch Tuesday", "u")
	if !s.Fetched {
		t.Fatalf("source = %+v", s)
	}
	if lines := strings.Split(s.Text, "\n"); len(lines) != 3 {
		t.Errorf("text has %d lines, want 3:\n%s", len(lines), s.Text)
	}
	if !strings.Contains(s.Text, "<three>") {
		t.Error("angle brackets in copied text were treated as tags")
	}
}

func TestAnEmptySavedFileIsNotASource(t *testing.T) {
	p := write(t, t.TempDir(), "qualys.txt", "  \n")
	if s := LoadSaved(p, "Qualys blog", "u"); s.Fetched || s.Err == "" {
		t.Errorf("empty file accepted: %+v", s)
	}
}
