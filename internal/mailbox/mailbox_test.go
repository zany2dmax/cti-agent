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
	// The point of this case is that subject text does not delete mail. It is
	// now left rather than archived, but the property under test is the same:
	// anything short of a header saying "automatic reply" must not be deleted.
	if byID["subject"].Action == ActionDelete {
		t.Errorf("subject-only match must not be deleted: %s",
			byID["subject"].Action)
	}
	if byID["subject"].Action != ActionLeave {
		t.Errorf("a processed non-CVE message should be left alone: %s",
			byID["subject"].Action)
	}
}

// The first real dry run proposed archiving a message whose whole subject was
// "suspicious", a forwarded invoice, and a Defender attack-path alert, all
// because the agent had read them and found no CVE. This is a shared security
// mailbox: "read looking for CVEs" is not "triaged", and filing a colleague's
// phishing report before anyone looks at it is the quiet damage this lane was
// written to avoid.
func TestProcessedNonCVEMailIsLeftAloneNotArchived(t *testing.T) {
	proc := map[string]Processed{
		"phish":    {ID: "phish"},
		"invoice":  {ID: "invoice"},
		"defender": {ID: "defender"},
		"advisory": {ID: "advisory", HasCVE: true},
	}
	plan := Plan([]Candidate{
		{ID: "phish", Subject: "suspicious"},
		{ID: "invoice", Subject: "FW: Office Technologies Inc Invoice"},
		{ID: "defender", Subject: "Microsoft Defender found potential attack path"},
		{ID: "advisory", Subject: "Daily CTI Roundup"},
	}, proc)

	byID := map[string]Decision{}
	for _, d := range plan {
		byID[d.ID] = d
	}
	for _, id := range []string{"phish", "invoice", "defender"} {
		if byID[id].Action != ActionLeave {
			t.Errorf("%s: action = %s, want leave - %q",
				id, byID[id].Action, byID[id].Subject)
		}
		// Known, so it does not count towards the backlog alarm.
		if !byID[id].Known {
			t.Errorf("%s: should be marked Known; the agent did read it", id)
		}
	}
	// The CTI advisory is still archived. That is the whole job.
	if byID["advisory"].Action != ActionArchive {
		t.Errorf("advisory: action = %s, want archive", byID["advisory"].Action)
	}

	c := Summarise(plan)
	if c.Archive != 1 || c.Leave != 3 || c.Unread != 0 {
		t.Errorf("counts = %+v; want archive 1, leave 3, unread 0", c)
	}
}

// Leave has two causes that mean opposite things, and only one of them is a
// fault. Counting them together made the backlog alarm fire on a healthy
// mailbox, where ordinary team mail is left alone every day by design.
func TestTheBacklogAlarmCountsOnlyMailTheAgentNeverRead(t *testing.T) {
	plan := Plan([]Candidate{
		{ID: "read-1"}, {ID: "read-2"}, {ID: "read-3"},
		{ID: "never-read-1"}, {ID: "never-read-2"},
	}, map[string]Processed{
		"read-1": {ID: "read-1"}, "read-2": {ID: "read-2"}, "read-3": {ID: "read-3"},
	})
	c := Summarise(plan)
	if c.Leave != 5 {
		t.Errorf("Leave = %d, want 5", c.Leave)
	}
	if c.Unread != 2 {
		t.Errorf("Unread = %d, want 2 - only the two with no record", c.Unread)
	}
	if n := BacklogNote(c, 3); n != "" {
		t.Errorf("5 left but only 2 unread, threshold 3: should stay quiet, got %q", n)
	}
	if n := BacklogNote(c, 2); !strings.Contains(n, "2 message(s)") {
		t.Errorf("at the threshold it should fire and name the unread count: %q", n)
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
	if n := BacklogNote(Counts{Leave: 3, Unread: 3}, 25); n != "" {
		t.Errorf("below threshold should say nothing: %q", n)
	}
	n := BacklogNote(Counts{Leave: 25, Unread: 25}, 25)
	if !strings.Contains(n, "25 message(s)") {
		t.Errorf("note = %q", n)
	}
	if !strings.Contains(n, "stopped reading the mailbox") {
		t.Errorf("the note should name what a backlog usually means: %q", n)
	}
	if n := BacklogNote(Counts{Leave: 1000, Unread: 1000}, 0); n != "" {
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
	// "c" was read and carried no CVE, so it is left rather than archived;
	// "d" has no record at all, so it is left AND counts as unread.
	if c.Archive != 1 || c.Delete != 1 || c.Leave != 2 || c.Unread != 1 {
		t.Errorf("counts = %+v, want archive 1 delete 1 leave 2 unread 1", c)
	}
	if c.Archive+c.Delete+c.Leave != len(plan) {
		t.Error("every decision must be counted exactly once")
	}
	if c.Unread > c.Leave {
		t.Error("Unread is a subset of Leave and cannot exceed it")
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

// ------------------------------------------- what may move, and nothing else

// THE INVARIANT THIS LANE EXISTS UNDER.
//
// cybersecurity@ is not a feed, it is the team's shared reporting mailbox:
// everyone reads it, and its contents are how a new hire finds out what has
// been happening and how work survives somebody leaving. Mail moved out of it
// by a bot is institutional memory removed from the people who need it, and
// nobody is watching when this lane runs.
//
// So exactly two kinds of message may ever move: a CTI advisory the agent
// actually took a CVE from, and a message whose own headers declare it an
// automatic reply. Everything else stays where a human can see it. This table
// is the regression test for that, and it is written from the real subjects in
// the first production dry run - three of which this lane proposed to archive.
func TestOnlyCTIAdvisoriesAndAutoRepliesEverMove(t *testing.T) {
	cases := []struct {
		subject string
		rec     Processed
		hdrAuto bool
		want    Action
		why     string
	}{
		// The two things that may move.
		{"Daily Cyber Threat Intelligence Roundup - September 21, 2026",
			Processed{HasCVE: true}, false, ActionArchive,
			"a CTI advisory the agent took a CVE from - the lane's actual job"},
		{"[Sev5] CTI Sep 21: 3 exploited vulns present in the environment",
			Processed{HasCVE: true}, false, ActionArchive,
			"the fleet's own digest, which carries CVEs"},
		{"Automatic reply: CR Cyber Security Team - Important!",
			Processed{}, true, ActionDelete,
			"header-confirmed auto-reply"},

		// Everything a shared security mailbox actually receives. Every one of
		// these was archived by the first version of this rule.
		{"suspicious", Processed{}, false, ActionLeave,
			"a colleague reporting a phish, in one word, needing a human"},
		{"FW: Atlanta Office Technologies Inc Invoice", Processed{}, false, ActionLeave,
			"a forwarded invoice - almost certainly a reported phish"},
		{"Microsoft Defender for Cloud found potential attack path",
			Processed{}, false, ActionLeave, "an alert somebody has to action"},
		{"Qualys: Scheduled Web Application Vulnerability Scan Notification",
			Processed{}, false, ActionLeave, "scanner operations mail"},
		{"pathway missing again", Processed{}, false, ActionLeave,
			"a person writing to the team"},
		{"Please add the new starter to the security distribution list",
			Processed{}, false, ActionLeave, "onboarding - the exact thing a new hire needs to find"},
		{"Re: incident 4471 - can someone confirm the containment steps",
			Processed{}, false, ActionLeave, "an in-flight incident thread"},
		{"Your Microsoft 365 subscription receipt", Processed{}, false, ActionLeave,
			"billing, not ours to file"},
	}

	for _, c := range cases {
		rec := c.rec
		rec.ID = "id"
		plan := Plan([]Candidate{{ID: "id", Subject: c.subject, AutoReply: c.hdrAuto}},
			map[string]Processed{"id": rec})
		if plan[0].Action != c.want {
			t.Errorf("%-62q\n    got %s, want %s (%s)",
				c.subject, plan[0].Action, c.want, c.why)
		}
	}
}

// The decision must not depend on the subject line at all. Reading intent out
// of subject text is how a lane starts deleting a genuine advisory titled
// "Automatic reply: ..." or archiving a phishing report because it looks like
// a newsletter.
func TestTheSubjectLineHasNoInfluenceOnTheDecision(t *testing.T) {
	subjects := []string{
		"", "newsletter", "Automatic reply: out of office",
		"URGENT ACTION REQUIRED", "CVE-2026-1111 in Windows NTFS",
		"re: re: re: fw:", "suspicious",
	}
	for _, s := range subjects {
		// Same record every time: read, no CVE, no auto-reply header.
		plan := Plan([]Candidate{{ID: "x", Subject: s}},
			map[string]Processed{"x": {ID: "x"}})
		if plan[0].Action != ActionLeave {
			t.Errorf("subject %q changed the action to %s; only the "+
				"processed-message record and the headers may decide",
				s, plan[0].Action)
		}
	}
	// And a CVE-bearing message is archived even when its subject looks like
	// an out-of-office reply.
	plan := Plan([]Candidate{{ID: "y", Subject: "Automatic reply: out of office"}},
		map[string]Processed{"y": {ID: "y", HasCVE: true}})
	if plan[0].Action != ActionArchive {
		t.Errorf("a CVE-bearing message must be archived, not %s - deleting a "+
			"genuine advisory is a loss, archiving an auto-reply is untidy",
			plan[0].Action)
	}
}

// Every input combination, enumerated. Plan has four rules whose ORDER carries
// the safety properties, and a truth table is the only way a future edit to
// that order shows up as a test failure rather than as mail going missing.
func TestEveryInputCombinationIsPinnedDown(t *testing.T) {
	cases := []struct {
		haveRecord bool
		hasCVE     bool
		recAuto    bool
		hdrAuto    bool
		want       Action
		why        string
	}{
		// No record: leave, absolutely, whatever anything else says.
		{false, false, false, false, ActionLeave, "never read"},
		{false, false, false, true, ActionLeave,
			"never read, and an auto-reply header cannot override that"},

		// Carries a CVE: archive, whatever else it looks like.
		{true, true, false, false, ActionArchive, "advisory"},
		{true, true, false, true, ActionArchive,
			"advisory whose headers also say auto-reply - archive wins over delete"},
		{true, true, true, false, ActionArchive, "same, recorded as an auto-reply"},
		{true, true, true, true, ActionArchive, "same, both flags set"},

		// No CVE, declared an auto-reply: delete.
		{true, false, true, false, ActionDelete, "recorded as an auto-reply"},
		{true, false, false, true, ActionDelete, "header says auto-reply"},
		{true, false, true, true, ActionDelete, "both say auto-reply"},

		// Read, no CVE, not an auto-reply: leave. The case that was archive.
		{true, false, false, false, ActionLeave, "read, and not this lane's mail"},
	}

	for _, c := range cases {
		proc := map[string]Processed{}
		if c.haveRecord {
			proc["id"] = Processed{ID: "id", HasCVE: c.hasCVE, AutoReply: c.recAuto}
		}
		plan := Plan([]Candidate{{ID: "id", AutoReply: c.hdrAuto}}, proc)
		if plan[0].Action != c.want {
			t.Errorf("record=%v cve=%v recAuto=%v hdrAuto=%v -> %s, want %s (%s)",
				c.haveRecord, c.hasCVE, c.recAuto, c.hdrAuto,
				plan[0].Action, c.want, c.why)
		}
		if plan[0].Known != c.haveRecord {
			t.Errorf("record=%v -> Known=%v", c.haveRecord, plan[0].Known)
		}
		if plan[0].Reason == "" {
			t.Error("every decision needs a reason; this lane has to be " +
				"explainable from the log alone")
		}
	}
}

// A plan is the input to something that moves other people's mail, so it may
// only ever contain the three actions this package defines. An unrecognised
// value would fall through the switch in cmd/cti-mailbox and do nothing, which
// is safe - but it would also fall through Summarise and go uncounted, so the
// printed plan would not add up to the number of messages.
func TestAPlanContainsNothingButTheThreeKnownActions(t *testing.T) {
	plan := Plan([]Candidate{
		{ID: "a"}, {ID: "b", AutoReply: true}, {ID: "c"}, {ID: "d"},
	}, map[string]Processed{
		"a": {ID: "a", HasCVE: true},
		"b": {ID: "b"},
		"c": {ID: "c"},
	})
	for _, d := range plan {
		switch d.Action {
		case ActionArchive, ActionDelete, ActionLeave:
		default:
			t.Errorf("unknown action %q for %q", d.Action, d.ID)
		}
	}
	c := Summarise(plan)
	if c.Archive+c.Delete+c.Leave != len(plan) {
		t.Errorf("counts %+v do not add up to %d decisions", c, len(plan))
	}
}
