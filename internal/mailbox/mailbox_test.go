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
	// "Make sure a given email has been processed" - for everything except
	// an automatic reply, which since 1.3.2 goes to Deleted Items on sight
	// (its own test below). None of these may move.
	cands := []Candidate{
		{ID: "unread-1", Subject: "Re: Out of Office plans for December"},
		{ID: "unread-2", Subject: "Daily CTI digest"},
		{ID: "unread-3", Subject: "anything at all"},
	}
	for _, d := range planNoGrace(cands, map[string]Processed{}) {
		if d.Action != ActionLeave {
			t.Errorf("%s: action %s - an unread message must never move", d.ID, d.Action)
		}
		if !strings.Contains(d.Reason, "no record") {
			t.Errorf("%s: reason %q should say why", d.ID, d.Reason)
		}
	}
}

// The operator's rule (1.3.2): automatic replies always go to Deleted Items.
// Below the processed rule they only went when the digest happened to have
// recorded them, and the inbox kept every out-of-office that arrived after
// the morning read.
func TestAutoRepliesAreDeletedEvenUnread(t *testing.T) {
	plan := planNoGrace([]Candidate{
		{ID: "hdr", Subject: "Re: your report", AutoReply: true},
		{ID: "subj", Subject: "Automatic reply: Out of Office"},
	}, map[string]Processed{})
	for _, d := range plan {
		if d.Action != ActionDelete {
			t.Errorf("%s: %s, want delete", d.ID, d.Action)
		}
		if d.Known {
			t.Errorf("%s: an unread auto-reply must not be counted as read", d.ID)
		}
	}
}

func TestAnUnreadSubjectOnlyMatchWaitsForTheDigest(t *testing.T) {
	// A real advisory titled "Automatic reply: ..." arriving at 06:50 must not
	// be deleted at 07:00 before the digest has read it - the CVE exception
	// only protects a message with a record.
	now := at(7)
	opt := Options{Now: now, SubjectGrace: 24 * time.Hour}
	got := PlanWith([]Candidate{
		{ID: "fresh", Subject: "Automatic reply: CVE-2026-1 advisory", Received: now.Add(-10 * time.Minute)},
		{ID: "old", Subject: "Automatic reply: away", Received: now.Add(-25 * time.Hour)},
		{ID: "hdr", Subject: "Re: x", AutoReply: true, Received: now.Add(-time.Minute)},
	}, map[string]Processed{}, opt)
	by := map[string]Action{}
	for _, d := range got {
		by[d.ID] = d.Action
	}
	if by["fresh"] != ActionLeave {
		t.Errorf("fresh subject-only match: %s, want leave until the digest reads it", by["fresh"])
	}
	if by["old"] != ActionDelete {
		t.Errorf("subject-only match older than the grace: %s, want delete", by["old"])
	}
	if by["hdr"] != ActionDelete {
		t.Errorf("header-declared auto-reply is never held: %s", by["hdr"])
	}
}

func TestAutoReplySubjectsAreMatchedAtTheStartOnly(t *testing.T) {
	for _, s := range []string{
		"Automatic reply: Out of Office", "  automatic REPLY: x",
		"Out of Office: back Monday", "Autoreply: away",
		"Automatische Antwort: abwesend",
	} {
		if !AutoReplySubject(s) {
			t.Errorf("%q should match", s)
		}
	}
	for _, s := range []string{
		"Re: Automatic reply: Out of Office", "FW: Out of Office: x",
		"Out of office plans", "CVE-2026-1 automatic reply bypass", "",
		"OOO: Friday", // a colleague's own notice, written by a person
	} {
		if AutoReplySubject(s) {
			t.Errorf("%q must not match - a prefix, not a substring", s)
		}
	}
}

func TestACVEBearingMessageIsArchivedNeverDeleted(t *testing.T) {
	// A SUBJECT-only auto-reply match the digest took a CVE from is archived:
	// anyone can title a message "Automatic reply:", and a real advisory under
	// that subject is evidence. A message whose HEADERS declare it an
	// auto-reply is deleted whatever it quoted - the operator's "always".
	proc := map[string]Processed{
		"subj": {ID: "subj", HasCVE: true},
		"hdr":  {ID: "hdr", HasCVE: true, AutoReply: true},
	}
	byID := map[string]Decision{}
	for _, d := range planNoGrace([]Candidate{
		{ID: "subj", Subject: "Automatic reply: re CVE-2026-1"},
		{ID: "hdr", Subject: "Automatic reply: re CVE-2026-1", AutoReply: true},
	}, proc) {
		byID[d.ID] = d
	}
	if byID["subj"].Action != ActionArchive {
		t.Errorf("subject-only + CVE: %s, want archive", byID["subj"].Action)
	}
	if byID["hdr"].Action != ActionDelete {
		t.Errorf("header-declared auto-reply: %s, want delete", byID["hdr"].Action)
	}
}

func TestHeaderAndSubjectAutoRepliesAreBothDeleted(t *testing.T) {
	proc := map[string]Processed{
		"ooo":     {ID: "ooo", AutoReply: true},
		"subject": {ID: "subject"},
	}
	for _, d := range planNoGrace([]Candidate{
		{ID: "ooo", Subject: "Re: hello", AutoReply: true},
		{ID: "subject", Subject: "Automatic reply: Out of Office"},
	}, proc) {
		if d.Action != ActionDelete {
			t.Errorf("%s: %s, want delete", d.ID, d.Action)
		}
		if !d.Known {
			t.Errorf("%s: it was read, so it is Known", d.ID)
		}
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
	plan := planNoGrace([]Candidate{
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
	plan := planNoGrace([]Candidate{
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
	plan := planNoGrace([]Candidate{
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
	plan := planNoGrace([]Candidate{{ID: "a"}, {ID: "b"}, {ID: "c"}},
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
// So only three kinds of message may ever move: mail a lane OWNS and has read
// (a CTI advisory the digest took a CVE from, a Qualys WAS notification the
// application-security weekly reported on), and an automatic reply. Everything
// else stays where a human can see it. This table
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
		{"Qualys: Scheduled Web Application Vulnerability Scan Notification",
			Processed{Owner: OwnerAppScan}, false, ActionArchive,
			"a scan notice the appscan weekly reported on - its owner has seen it"},

		// Everything a shared security mailbox actually receives. Every one of
		// these was archived by the first version of this rule.
		{"suspicious", Processed{}, false, ActionLeave,
			"a colleague reporting a phish, in one word, needing a human"},
		{"FW: Atlanta Office Technologies Inc Invoice", Processed{}, false, ActionLeave,
			"a forwarded invoice - almost certainly a reported phish"},
		{"Microsoft Defender for Cloud found potential attack path",
			Processed{}, false, ActionLeave, "an alert somebody has to action"},
		{"Qualys: Scheduled Web Application Vulnerability Scan Notification",
			Processed{}, false, ActionLeave,
			"the same notice before its owner has read it - the digest seeing it is not enough"},
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
		plan := planNoGrace([]Candidate{{ID: "id", Subject: c.subject, AutoReply: c.hdrAuto}},
			map[string]Processed{"id": rec})
		if plan[0].Action != c.want {
			t.Errorf("%-62q\n    got %s, want %s (%s)",
				c.subject, plan[0].Action, c.want, c.why)
		}
	}
}

// The subject line influences exactly one thing: a subject that STARTS like an
// out-of-office. Anything else in it - urgency, a CVE number, "newsletter" -
// changes nothing; reading intent out of subject text is how a lane starts
// archiving a phishing report because it looks like a newsletter.
func TestTheSubjectLineOnlyMattersAsAnAutoReplyPrefix(t *testing.T) {
	subjects := []string{
		"", "newsletter", "Re: Automatic reply: out of office",
		"URGENT ACTION REQUIRED", "CVE-2026-1111 in Windows NTFS",
		"re: re: re: fw:", "suspicious",
	}
	for _, s := range subjects {
		// Same record every time: read, no CVE, no owner, no header.
		plan := planNoGrace([]Candidate{{ID: "x", Subject: s}},
			map[string]Processed{"x": {ID: "x"}})
		if plan[0].Action != ActionLeave {
			t.Errorf("subject %q changed the action to %s", s, plan[0].Action)
		}
	}
	plan := planNoGrace([]Candidate{{ID: "y", Subject: "Automatic reply: out of office"}},
		map[string]Processed{"y": {ID: "y", HasCVE: true}})
	if plan[0].Action != ActionArchive {
		t.Errorf("a CVE-bearing message with an auto-reply subject must be "+
			"archived, not %s - deleting a genuine advisory is a loss",
			plan[0].Action)
	}
}

// Every input combination, enumerated. The ORDER of Plan's rules carries the
// safety properties, and a truth table is the only way a future edit to that
// order shows up as a test failure rather than as mail going missing.
func TestEveryInputCombinationIsPinnedDown(t *testing.T) {
	type in struct {
		record, cve, recAuto, hdrAuto, subjAuto bool
		owner                                   string
	}
	cases := []struct {
		in   in
		want Action
		why  string
	}{
		// Auto-replies first, read or not.
		{in{hdrAuto: true}, ActionDelete, "unread, header says auto-reply"},
		{in{subjAuto: true}, ActionDelete, "unread, subject says auto-reply"},
		{in{record: true, recAuto: true}, ActionDelete, "recorded as an auto-reply"},
		{in{record: true, cve: true, hdrAuto: true}, ActionDelete,
			"headers outrank a quoted CVE"},
		{in{record: true, cve: true, subjAuto: true}, ActionArchive,
			"subject only, with a CVE: evidence, archived"},
		{in{record: true, owner: OwnerAppScan, subjAuto: true}, ActionDelete,
			"subject auto-reply with no CVE, owner or not"},

		// Not an auto-reply, never read: leave, whatever else.
		{in{}, ActionLeave, "never read"},

		// Read by its owner: archive.
		{in{record: true, cve: true}, ActionArchive, "digest-owned advisory"},
		{in{record: true, owner: OwnerAppScan}, ActionArchive, "appscan-owned notice"},
		{in{record: true, cve: true, owner: OwnerAppScan}, ActionArchive, "both"},

		// Read, no owner: leave.
		{in{record: true}, ActionLeave, "read, and no lane owns it"},
	}
	for _, c := range cases {
		proc := map[string]Processed{}
		if c.in.record {
			proc["id"] = Processed{ID: "id", HasCVE: c.in.cve,
				AutoReply: c.in.recAuto, Owner: c.in.owner}
		}
		subject := "Weekly notes"
		if c.in.subjAuto {
			subject = "Automatic reply: away"
		}
		plan := planNoGrace([]Candidate{{ID: "id", Subject: subject,
			AutoReply: c.in.hdrAuto}}, proc)
		if plan[0].Action != c.want {
			t.Errorf("%+v -> %s, want %s (%s)", c.in, plan[0].Action, c.want, c.why)
		}
		if plan[0].Known != c.in.record {
			t.Errorf("%+v -> Known=%v", c.in, plan[0].Known)
		}
		if plan[0].Reason == "" {
			t.Error("every decision needs a reason")
		}
	}
}

// On a day no CTI email was processed nothing is filed away - but
// auto-replies still go, which needs no fleet health at all.
func TestAHeldDayStillDeletesAutoRepliesButArchivesNothing(t *testing.T) {
	now := at(9)
	plan := PlanWith([]Candidate{
		{ID: "adv", Received: now.Add(-72 * time.Hour)},
		{ID: "ooo", Subject: "Automatic reply: away", Received: now},
		{ID: "own", SelfSent: true, Received: now},
	}, map[string]Processed{"adv": {ID: "adv", HasCVE: true}},
		Options{Now: now, HoldArchive: "no CTI email processed today"})
	byID := map[string]Decision{}
	for _, d := range plan {
		byID[d.ID] = d
	}
	if byID["adv"].Action != ActionLeave || !strings.Contains(byID["adv"].Reason, "no CTI email") {
		t.Errorf("held advisory: %s %q", byID["adv"].Action, byID["adv"].Reason)
	}
	if byID["ooo"].Action != ActionDelete {
		t.Errorf("auto-reply on a held day: %s", byID["ooo"].Action)
	}
	if byID["own"].Action != ActionArchive {
		t.Errorf("our own report on a held day: %s", byID["own"].Action)
	}
}

func TestMergeGivesOwnerLanesTheirMail(t *testing.T) {
	digest := map[string]Processed{
		"both": {ID: "both", AutoReply: false},
		"cve":  {ID: "cve", HasCVE: true},
	}
	appscan := &Log{Entries: []Processed{
		{ID: "both", Owner: OwnerAppScan, ReadAt: at(6)},
		{ID: "only", Owner: OwnerAppScan, ReadAt: at(6)},
		{ID: "noowner", ReadAt: at(6)}, // claims nothing
		{ID: "expired", Owner: OwnerAppScan, ReadAt: at(6).Add(-15 * 24 * time.Hour)},
	}}
	m := Merge(at(9), digest, appscan, nil)
	if m["both"].Owner != OwnerAppScan || m["only"].Owner != OwnerAppScan {
		t.Errorf("owner not merged: %+v", m)
	}
	if _, ok := m["noowner"]; ok {
		t.Error("an owner-log entry without an owner was treated as a record")
	}
	if _, ok := m["expired"]; ok {
		t.Error("an expired owner record still carries authority to move mail")
	}
	if !m["cve"].HasCVE || len(digest) != 2 {
		t.Error("the digest's index was changed or lost")
	}
}

func TestOwnerLogPath(t *testing.T) {
	t.Setenv("FLEET_PROCESSED_LOG", "")
	t.Setenv("FLEET_HOME", "")
	if OwnerLogPath(OwnerAppScan) != "" {
		t.Error("no FLEET_HOME must mean no path")
	}
	t.Setenv("FLEET_HOME", "/var/lib/cti-agent")
	if got := OwnerLogPath(OwnerAppScan); got != "/var/lib/cti-agent/state/processed-appscan.json" {
		t.Errorf("path = %q", got)
	}
	t.Setenv("FLEET_PROCESSED_LOG", "/tmp/dev/processed.json")
	if got := OwnerLogPath(OwnerAppScan); got != "/tmp/dev/processed-appscan.json" {
		t.Errorf("an overridden digest log must take the lane logs with it: %q", got)
	}
	for _, bad := range []string{"", "../x", "a/b", "a.b"} {
		if OwnerLogPath(bad) != "" {
			t.Errorf("owner %q must not produce a path", bad)
		}
	}
}

// A plan is the input to something that moves other people's mail, so it may
// only ever contain the three actions this package defines. An unrecognised
// value would fall through the switch in cmd/cti-mailbox and do nothing, which
// is safe - but it would also fall through Summarise and go uncounted, so the
// printed plan would not add up to the number of messages.
func TestAPlanContainsNothingButTheThreeKnownActions(t *testing.T) {
	plan := planNoGrace([]Candidate{
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

// planNoGrace is Plan with the minimum-age grace disabled.
//
// Every test above predates minAge and asserts the classification rules -
// processed, CVE, auto-reply, unknown - none of which the grace changes.
// Passing 0 keeps them asserting exactly what they were written to assert,
// rather than quietly becoming age tests. The grace has its own tests.
func planNoGrace(c []Candidate, p map[string]Processed) []Decision {
	return Plan(c, p, time.Now(), 0)
}

// ─── our own reports coming back round ──────────────────────────────────────
//
// The digest is sent TO the mailbox it READS, so every report arrives as
// input. cti-agent now skips its own mail before recording anything - which
// means these messages can never acquire a processed-log entry, and rule 1
// ("no record -> leave, absolute") would keep them in the inbox forever.

func TestOurOwnReportsAreArchivedNotLeftForever(t *testing.T) {
	plan := planNoGrace([]Candidate{
		{ID: "d1", Subject: "[Sev5] CTI Oct 03", Received: at(9), SelfSent: true},
	}, map[string]Processed{}) // deliberately empty: they are never processed

	if plan[0].Action != ActionArchive {
		t.Fatalf("Action = %q, want archive - rule 1 would leave it forever",
			plan[0].Action)
	}
	if !strings.Contains(plan[0].Reason, "sent by this fleet") {
		t.Errorf("Reason = %q, must say why this bypassed the processed check",
			plan[0].Reason)
	}
}

func TestOurOwnReportsAreNeverDeleted(t *testing.T) {
	// Archive, not delete. Deleting our own audit trail out of a shared
	// mailbox on a schedule with nobody watching is not a tidiness decision.
	plan := planNoGrace([]Candidate{
		{ID: "d1", Subject: "CTI digest", Received: at(9),
			SelfSent: true, AutoReply: true}, // even if it looks auto-generated
	}, map[string]Processed{})

	if plan[0].Action == ActionDelete {
		t.Error("the fleet's own report was deleted")
	}
}

func TestOurOwnReportsDoNotCountTowardsTheBacklogAlarm(t *testing.T) {
	// The alarm means "the agent has stopped reading the mailbox". Our own
	// reports accumulating would make it fire on a mailbox being read
	// perfectly well - an alarm that cries wolf is an alarm that gets muted,
	// and this one is the detector for the agent going dark.
	cands := make([]Candidate, 0, 40)
	for i := 0; i < 40; i++ {
		cands = append(cands, Candidate{
			ID: string(rune('a' + i%26)), Subject: "CTI digest",
			Received: at(9), SelfSent: true,
		})
	}
	counts := Summarise(planNoGrace(cands, map[string]Processed{}))

	if note := BacklogNote(counts, 25); note != "" {
		t.Errorf("40 of our own reports raised the backlog alarm:\n  %s", note)
	}
}

func TestARealAdvisoryIsStillGovernedByTheProcessedRule(t *testing.T) {
	// The new rule must not become a general bypass. Anything not self-sent
	// still cannot be touched without a processing record.
	plan := planNoGrace([]Candidate{
		{ID: "v1", Subject: "Vendor advisory", Received: at(9), SelfSent: false},
	}, map[string]Processed{})

	if plan[0].Action != ActionLeave {
		t.Errorf("Action = %q, want leave", plan[0].Action)
	}
}

// ─── the minimum-age grace ──────────────────────────────────────────────────

func TestAJustArrivedAdvisoryIsLeftForTheTeamToRead(t *testing.T) {
	// The behaviour that prompted this: a manual run after the morning digest
	// archived two roundups that had arrived hours earlier, while the same
	// lane on its timer - which fires BEFORE the digest - would have left
	// them. Same code, same mailbox, different outcome by clock position.
	now := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	c := Candidate{ID: "m1", Subject: "Daily CTI Roundup",
		Received: now.Add(-7 * time.Hour)}
	proc := map[string]Processed{"m1": {HasCVE: true}}

	got := Plan([]Candidate{c}, proc, now, 24*time.Hour)
	if got[0].Action != ActionLeave {
		t.Errorf("a 7-hour-old advisory was archived: %v", got[0].Action)
	}
	if !strings.Contains(got[0].Reason, "still read it there") {
		t.Errorf("reason does not explain the wait: %q", got[0].Reason)
	}
}

func TestOnceItIsOldEnoughItIsArchived(t *testing.T) {
	now := time.Date(2026, 10, 2, 7, 0, 0, 0, time.UTC)
	c := Candidate{ID: "m1", Received: now.Add(-25 * time.Hour)}
	proc := map[string]Processed{"m1": {HasCVE: true}}

	if got := Plan([]Candidate{c}, proc, now, 24*time.Hour); got[0].Action != ActionArchive {
		t.Errorf("a 25-hour-old processed advisory was not archived: %v", got[0].Action)
	}
}

func TestTheGraceBoundaryIsNotOffByOne(t *testing.T) {
	// Exactly minAge old must archive. An advisory that is forever "not quite
	// old enough" is the leak this was meant to close, reintroduced one hour
	// later.
	now := time.Date(2026, 10, 2, 7, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		age  time.Duration
		want Action
	}{
		{23*time.Hour + 59*time.Minute, ActionLeave},
		{24 * time.Hour, ActionArchive},
		{24*time.Hour + time.Minute, ActionArchive},
	} {
		c := Candidate{ID: "m1", Received: now.Add(-tc.age)}
		proc := map[string]Processed{"m1": {HasCVE: true}}
		if got := Plan([]Candidate{c}, proc, now, 24*time.Hour)[0].Action; got != tc.want {
			t.Errorf("age %s: got %v, want %v", tc.age, got, tc.want)
		}
	}
}

func TestTheGraceDoesNotDelayDeletingAutoReplies(t *testing.T) {
	// The grace exists so a colleague can still read an advisory in the
	// inbox. Nobody wants to read a bounce, so auto-replies go on sight.
	now := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	c := Candidate{ID: "m1", Received: now.Add(-1 * time.Minute), AutoReply: true}
	proc := map[string]Processed{"m1": {HasCVE: false}}

	if got := Plan([]Candidate{c}, proc, now, 24*time.Hour); got[0].Action != ActionDelete {
		t.Errorf("a one-minute-old auto-reply was held by the grace: %v", got[0].Action)
	}
}

func TestTheGraceNeverPromotesAMessageToArchive(t *testing.T) {
	// An unprocessed message must stay LEAVE whatever its age. The grace can
	// only ever delay an archive, never cause one - that rule is the
	// operator's "make sure a given email has been processed", and age must
	// not become a back door around it.
	now := time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)
	c := Candidate{ID: "ancient", Received: now.Add(-100 * 24 * time.Hour)}
	got := Plan([]Candidate{c}, map[string]Processed{}, now, 24*time.Hour)
	if got[0].Action != ActionLeave {
		t.Errorf("an unprocessed message was acted on: %v", got[0].Action)
	}
	if got[0].Known {
		t.Error("an unprocessed message was marked known")
	}
}

func TestAZeroGraceKeepsTheOldBehaviour(t *testing.T) {
	now := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	c := Candidate{ID: "m1", Received: now.Add(-1 * time.Minute)}
	proc := map[string]Processed{"m1": {HasCVE: true}}
	if got := Plan([]Candidate{c}, proc, now, 0); got[0].Action != ActionArchive {
		t.Errorf("minAge=0 should archive immediately: %v", got[0].Action)
	}
}
