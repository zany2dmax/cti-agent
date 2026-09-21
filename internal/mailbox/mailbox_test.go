package mailbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(h int) time.Time {
	return time.Date(2026, time.September, 21, h, 0, 0, 0, time.UTC)
}

// ---------------------------------------------------------------- the gate

func TestNothingIsTouchedWithoutAProcessingRecord(t *testing.T) {
	// The operator's rule, and the only one that cannot be overridden by any
	// other: "make sure a given email has been processed before deleting it".
	//
	// Every candidate here looks deletable - one is a textbook auto-reply -
	// and none of them may move, because nothing recorded reading them.
	cands := []Candidate{
		{ID: "unread-1", Subject: "Automatic reply: Out of Office", AutoReply: true},
		{ID: "unread-2", Subject: "Daily CTI digest"},
		{ID: "unread-3", Subject: "anything at all"},
	}
	for _, d := range Plan(cands, map[string]Processed{}) {
		if d.Action != ActionLeave {
			t.Errorf("%s: action %s - an unread message must never move", d.ID, d.Action)
		}
		if !strings.Contains(d.Reason, "no record") {
			t.Errorf("%s: reason %q should say why", d.ID, d.Reason)
		}
	}
}

func TestACVEBearingMessageIsArchivedNeverDeleted(t *testing.T) {
	// Precedence test. A message that contributed a finding is evidence. If it
	// also carries auto-reply headers - an out-of-office that quoted an
	// advisory back, which happens - archiving is the wrong-but-recoverable
	// outcome and deleting is the loss.
	proc := map[string]Processed{
		"m1": {ID: "m1", HasCVE: true, AutoReply: true},
	}
	got := Plan([]Candidate{{ID: "m1", Subject: "Automatic reply: re CVE-2026-1", AutoReply: true}}, proc)
	if got[0].Action != ActionArchive {
		t.Errorf("action = %s, want archive: a CVE outranks an auto-reply header", got[0].Action)
	}
}

func TestOnlyHeaderConfirmedAutoRepliesAreDeleted(t *testing.T) {
	proc := map[string]Processed{
		"ooo":     {ID: "ooo", AutoReply: true},
		"subject": {ID: "subject", AutoReply: false},
	}
	plan := Plan([]Candidate{
		{ID: "ooo", Subject: "Automatic reply: Out of Office", AutoReply: true},
		// Looks exactly like an auto-reply and is not one, as far as the
		// headers are concerned. Subject text does not delete mail.
		{ID: "subject", Subject: "Automatic reply: Out of Office"},
	}, proc)
	byID := map[string]Decision{}
	for _, d := range plan {
		byID[d.ID] = d
	}
	if byID["ooo"].Action != ActionDelete {
		t.Errorf("header-confirmed auto-reply: %s", byID["ooo"].Action)
	}
	if byID["subject"].Action != ActionArchive {
		t.Errorf("subject-only match should be archived, not deleted: %s",
			byID["subject"].Action)
	}
}

func TestProcessedNonCVEMailIsArchived(t *testing.T) {
	proc := map[string]Processed{"m": {ID: "m"}}
	got := Plan([]Candidate{{ID: "m", Subject: "vendor newsletter"}}, proc)
	if got[0].Action != ActionArchive {
		t.Errorf("action = %s, want archive", got[0].Action)
	}
}

// ---------------------------------------------------------------- the day gate

func TestTheLaneOnlyRunsOnADayACTIEmailWasProcessed(t *testing.T) {
	loc := time.UTC
	l := &Log{}

	// Nothing at all.
	if ok, n := l.ProcessedToday(at(9), loc); ok || n != 0 {
		t.Errorf("empty log: ok=%v n=%d", ok, n)
	}

	// Read today, but nothing carried a CVE - an inbox full of out-of-office
	// replies is not a processed CTI day.
	l.Entries = []Processed{{ID: "a", HasCVE: false, ReadAt: at(6)}}
	if ok, _ := l.ProcessedToday(at(9), loc); ok {
		t.Error("auto-replies alone must not count as a processed CTI email")
	}

	// A CVE-bearing message today.
	l.Entries = append(l.Entries, Processed{ID: "b", HasCVE: true, ReadAt: at(6)})
	if ok, n := l.ProcessedToday(at(9), loc); !ok || n != 1 {
		t.Errorf("ok=%v n=%d, want true 1", ok, n)
	}

	// Yesterday's CVE does not license today's cleanup.
	l.Entries = []Processed{{ID: "c", HasCVE: true, ReadAt: at(6).Add(-24 * time.Hour)}}
	if ok, _ := l.ProcessedToday(at(9), loc); ok {
		t.Error("yesterday's processing must not authorise today's cleanup")
	}
}

func TestTheDayBoundaryFollowsTheConfiguredZone(t *testing.T) {
	// The digest runs at 06:00 local and this lane runs after it. If "today"
	// were UTC, an early-morning run in a western timezone would look at
	// yesterday and refuse - the same class of bug as the digest that fired at
	// 2am because OnCalendar has no zone.
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	// 01:00 on the 22nd in New York is 05:00 UTC on the 22nd; a message read
	// at 23:00 UTC on the 21st is 19:00 on the 21st in New York - yesterday
	// either way. Read at 05:30 UTC on the 22nd it is 01:30 local: today.
	l := &Log{Entries: []Processed{{ID: "x", HasCVE: true,
		ReadAt: time.Date(2026, 9, 22, 5, 30, 0, 0, time.UTC)}}}
	now := time.Date(2026, 9, 22, 6, 0, 0, 0, time.UTC)
	if ok, _ := l.ProcessedToday(now, ny); !ok {
		t.Error("a message read 30 minutes ago should count as today")
	}
	l.Entries[0].ReadAt = time.Date(2026, 9, 21, 23, 0, 0, 0, time.UTC)
	if ok, _ := l.ProcessedToday(now, ny); ok {
		t.Error("19:00 the previous local day is not today")
	}
}

// ---------------------------------------------------------------- the log

func TestTheLogRoundTripsAndDedupesByID(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "state", "processed.json"),
		Now: func() time.Time { return at(6) }, Retain: DefaultRetain}

	l, err := s.Load()
	if err != nil {
		t.Fatalf("a missing log is an empty log, not an error: %v", err)
	}
	s.Record(l, []Processed{
		{ID: "m1", Subject: "first", HasCVE: true},
		{ID: "m2", Subject: "ooo", AutoReply: true},
	})
	// A second run sees m1 again; it must not double up, and the newer view
	// wins - a message can gain a CVE if the body was updated, or be
	// reclassified.
	s.Record(l, []Processed{{ID: "m1", Subject: "first, again", HasCVE: true}})
	if err := s.Save(l); err != nil {
		t.Fatalf("save: %v", err)
	}

	again, err := s.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(again.Entries) != 2 {
		t.Fatalf("got %d entries, want 2 (m1 deduped)", len(again.Entries))
	}
	idx := again.Index()
	if idx["m1"].Subject != "first, again" {
		t.Errorf("later record should win: %q", idx["m1"].Subject)
	}
	if !idx["m2"].AutoReply {
		t.Error("auto-reply flag lost in the round trip")
	}

	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	// Subject lines from a security mailbox.
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode %o, want 600", perm)
	}
}

func TestOldEntriesExpireSoOldAuthorityDoes(t *testing.T) {
	// Retention is not only about file size. While an entry exists, the lane
	// may move that message; letting entries live forever means an advisory
	// read a year ago could still be archived by a run today on the strength
	// of a record nobody remembers.
	s := &Store{Path: filepath.Join(t.TempDir(), "p.json"),
		Now: func() time.Time { return at(6) }, Retain: 48 * time.Hour}
	l := &Log{}
	s.Record(l, []Processed{
		{ID: "fresh", ReadAt: at(6).Add(-1 * time.Hour)},
		{ID: "stale", ReadAt: at(6).Add(-72 * time.Hour)},
	})
	idx := l.Index()
	if _, ok := idx["fresh"]; !ok {
		t.Error("a recent entry was pruned")
	}
	if _, ok := idx["stale"]; ok {
		t.Error("an entry past the retention window still authorises a move")
	}
}

func TestACorruptLogIsAnErrorNotAnEmptyOne(t *testing.T) {
	// Asymmetric with the budget ledger on purpose. An empty budget ledger
	// means "spend a beat", which is harmless. Silently treating a truncated
	// processed log as empty would mean the inbox quietly stops being tidied
	// with nothing to show why.
	p := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(p, []byte(`{"entries":[{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(p).Load(); err == nil {
		t.Error("a corrupt log must be an error so somebody fixes it")
	}
}

func TestLogPathIsEmptyWithoutAStateDirectory(t *testing.T) {
	// The agent also runs by hand from a checkout. A log written to whatever
	// directory the binary started in would hand the cleanup lane a set of
	// message IDs from a developer's laptop.
	t.Setenv("FLEET_PROCESSED_LOG", "")
	t.Setenv("FLEET_HOME", "")
	if got := LogPath(); got != "" {
		t.Errorf("LogPath() = %q, want empty with no FLEET_HOME", got)
	}
	t.Setenv("FLEET_HOME", "/var/lib/cti-agent")
	if got := LogPath(); got != "/var/lib/cti-agent/state/processed-messages.json" {
		t.Errorf("LogPath() = %q", got)
	}
	t.Setenv("FLEET_PROCESSED_LOG", "/tmp/override.json")
	if got := LogPath(); got != "/tmp/override.json" {
		t.Errorf("explicit override ignored: %q", got)
	}
}

// ---------------------------------------------------------------- reporting

func TestTheBacklogNoteOnlyFiresAtTheThreshold(t *testing.T) {
	if n := BacklogNote(Counts{Leave: 3}, 25); n != "" {
		t.Errorf("below threshold should say nothing: %q", n)
	}
	n := BacklogNote(Counts{Leave: 25}, 25)
	if !strings.Contains(n, "25 message(s)") {
		t.Errorf("note = %q", n)
	}
	if !strings.Contains(n, "stopped reading the mailbox") {
		t.Errorf("the note should name what a backlog usually means: %q", n)
	}
	if n := BacklogNote(Counts{Leave: 1000}, 0); n != "" {
		t.Error("threshold 0 disables the note")
	}
}

func TestSummariseCountsEveryAction(t *testing.T) {
	plan := Plan([]Candidate{
		{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"},
	}, map[string]Processed{
		"a": {ID: "a", HasCVE: true},
		"b": {ID: "b", AutoReply: true},
		"c": {ID: "c"},
	})
	c := Summarise(plan)
	if c.Archive != 2 || c.Delete != 1 || c.Leave != 1 {
		t.Errorf("counts = %+v, want archive 2 delete 1 leave 1", c)
	}
	if c.Archive+c.Delete+c.Leave != len(plan) {
		t.Error("every decision must be counted exactly once")
	}
}

func TestEveryDecisionCarriesAReason(t *testing.T) {
	// This lane moves other people's mail unattended. "Why is this in Deleted
	// Items" has to be answerable from the log alone.
	plan := Plan([]Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}},
		map[string]Processed{
			"a": {ID: "a", HasCVE: true},
			"b": {ID: "b", AutoReply: true},
		})
	for _, d := range plan {
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("%s (%s) has no reason", d.ID, d.Action)
		}
	}
}
