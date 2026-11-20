package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/mailbox"
)

// The owners lane records only a sent scan's COMPANION notices (the scheduled-
// scan notice, which no report uses) for the mailbox cleanup. A scan's results
// notice is the weekly's only source of counts, so it is never recorded here:
// it waits for the weekly, whatever happened to the scan's owner report. A held
// scan's notices, and any notice without the scanner's reference, wait too.
func TestCommitSeenOnlySentRecordsOnlyTheCompanionNoticesOfSentScans(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FLEET_HOME", home)
	t.Setenv("FLEET_PROCESSED_LOG", "")
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen.json")
	if err := writeSeen(seen, []mailbox.Processed{
		{ID: "sent-result", Ref: "WAS-1"},
		{ID: "sent-scheduled", Ref: "WAS-1", Delete: true},
		{ID: "held-result", Ref: "WAS-2"},
		{ID: "no-ref", Ref: ""},
	}); err != nil {
		t.Fatal(err)
	}
	sent := filepath.Join(dir, "sent.tsv")
	body := "app1\tWAS-1\tsent\napp2\tWAS-2\theld: the scan's login failed\n"
	if err := os.WriteFile(sent, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := doCommitSeen(seen, sent); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	l, err := mailbox.NewStore(mailbox.OwnerLogPath(mailbox.OwnerAppScan)).Load()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]mailbox.Processed{}
	for _, e := range l.Entries {
		got[e.ID] = e
	}
	if len(got) != 1 {
		t.Fatalf("recorded %v, want only the companion notice of the sent scan", got)
	}
	if e, ok := got["sent-scheduled"]; !ok || !e.Delete || e.Owner != mailbox.OwnerAppScan {
		t.Errorf("the companion notice lost its flags: %+v", got)
	}
	if _, ok := got["sent-result"]; ok {
		t.Error("a results notice was recorded for the cleanup before the weekly read it")
	}
}

func TestCommitSeenWithoutOnlySentRecordsEverything(t *testing.T) {
	t.Setenv("FLEET_HOME", t.TempDir())
	t.Setenv("FLEET_PROCESSED_LOG", "")
	seen := filepath.Join(t.TempDir(), "seen.json")
	_ = writeSeen(seen, []mailbox.Processed{{ID: "a", Ref: "WAS-1"}, {ID: "b"}})
	if rc := doCommitSeen(seen, ""); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	l, _ := mailbox.NewStore(mailbox.OwnerLogPath(mailbox.OwnerAppScan)).Load()
	if len(l.Entries) != 2 {
		t.Errorf("the weekly records every notice it covered, got %d", len(l.Entries))
	}
}

func TestCommitSeenOnlySentFailsOnAMissingSentList(t *testing.T) {
	t.Setenv("FLEET_HOME", t.TempDir())
	seen := filepath.Join(t.TempDir(), "seen.json")
	_ = writeSeen(seen, []mailbox.Processed{{ID: "a", Ref: "WAS-1"}})
	if rc := doCommitSeen(seen, filepath.Join(t.TempDir(), "absent.tsv")); rc == exitOK {
		t.Error("an unreadable sent list must not fall back to recording everything")
	}
}
