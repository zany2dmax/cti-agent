package mailbox

import (
	"strings"
	"testing"
	"time"
)

func TestStaleSweepMovesOldMailToTheFolderButLeavesFlaggedMail(t *testing.T) {
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	plan := PlanStale([]StaleCandidate{
		{ID: "b", Subject: "a reported phish", Received: now.AddDate(0, 0, -40)},
		{ID: "a", Subject: "flagged by a person", Received: now.AddDate(0, 0, -90), Flagged: true},
		{ID: "c", Subject: "Qualys scan notice", Received: now.AddDate(0, 0, -31)},
	}, now, 30*24*time.Hour, "Unhandled")
	if len(plan) != 3 {
		t.Fatalf("%d decisions", len(plan))
	}
	if plan[0].ID != "a" || plan[0].Action != ActionLeave || plan[0].Why != LeaveFlagged {
		t.Errorf("flagged: %+v - a person's flag must keep it in the inbox", plan[0])
	}
	for _, d := range plan[1:] {
		if d.Action != ActionUnhandled {
			t.Errorf("%s: %s, want unhandled", d.ID, d.Action)
		}
		if !strings.Contains(d.Reason, "Unhandled") || !strings.Contains(d.Reason, "days old") {
			t.Errorf("reason %q must say how old and where it went", d.Reason)
		}
	}
	for _, d := range plan {
		if d.Action == ActionArchive || d.Action == ActionDelete {
			t.Errorf("%s: the sweep must never archive or delete, got %s", d.ID, d.Action)
		}
	}
}

func TestEveryLeaveInTheDailyPlanSaysWhy(t *testing.T) {
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	cands := []Candidate{
		{ID: "never", Subject: "x", Received: now.Add(-9 * 24 * time.Hour)},
		{ID: "notmine", Subject: "suspicious", Received: now.Add(-72 * time.Hour)},
		{ID: "young", Subject: "advisory", Received: now.Add(-2 * time.Hour)},
		{ID: "self", Subject: "digest", Received: now.Add(-time.Hour), SelfSent: true},
		{ID: "oof", Subject: "Automatic reply: away", Received: now.Add(-time.Hour)},
		{ID: "quar", Subject: "digest", Received: now.Add(-time.Hour), QuarantineDigest: true},
	}
	proc := map[string]Processed{
		"notmine": {ID: "notmine"},
		"young":   {ID: "young", HasCVE: true},
	}
	plan := PlanWith(cands, proc, Options{Now: now, MinAge: 48 * time.Hour,
		SelfMinAge: 168 * time.Hour, SubjectGrace: 24 * time.Hour})
	for _, d := range plan {
		if d.Action == ActionLeave && d.Why == "" {
			t.Errorf("%s left with no Why: %q", d.ID, d.Reason)
		}
		if d.Action != ActionLeave && d.Why != "" {
			t.Errorf("%s moved (%s) but has Why %q", d.ID, d.Action, d.Why)
		}
	}
	s := Left(plan, now, 7*24*time.Hour)
	if s.ByWhy[LeaveNeverRead] != 1 || s.NeverReadOld != 1 || s.Oldest < 9*24*time.Hour {
		t.Errorf("summary %+v: one never-read message, 9 days old", s)
	}
	line := s.Line(7 * 24 * time.Hour)
	if !strings.HasPrefix(line, "LEFT: never-read=1 (1 over 7d, oldest 9d)") {
		t.Errorf("line %q: never-read comes first, with its age", line)
	}
	for _, want := range []string{"not-lane-mail=1", "owned-grace=1", "own-report-grace=1",
		"auto-reply-wait=1", "quarantine-unreadable=1"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %s", line, want)
		}
	}
}

func TestNeverReadMailUnderAWeekIsCountedButNotOld(t *testing.T) {
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	plan := []Decision{
		{Candidate: Candidate{ID: "a", Received: now.Add(-2 * 24 * time.Hour)}, Action: ActionLeave, Why: LeaveNeverRead},
	}
	s := Left(plan, now, 7*24*time.Hour)
	if s.ByWhy[LeaveNeverRead] != 1 || s.NeverReadOld != 0 {
		t.Errorf("%+v", s)
	}
	if got := Left(nil, now, 0).Line(0); got != "LEFT: nothing" {
		t.Errorf("empty plan: %q", got)
	}
}
