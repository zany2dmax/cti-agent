package main

import (
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

const noticeSubject = "Qualys: Web Application Vulnerability Scan Results - Example Shop Run #40"

// The real case: a scanner account whose notification sender is the team
// mailbox. graph marks anything From the mailbox SelfSent (unsigned), and the
// notice used to vanish at the self-sent skip without a word.
func TestANoticeFromTheMailboxItselfIsReportedNotDropped(t *testing.T) {
	m := graph.Message{ID: "1", Subject: noticeSubject,
		From: "team@example.com", SelfSent: true,
		BodyHTML: "<div>Scan Reference : was/5555555555555.66666666</div>"}
	scans, seen, problems := collect([]graph.Message{m})
	if len(scans) != 0 || len(seen) != 0 {
		t.Errorf("a lookalike was parsed (%d) or claimed (%d) - the sender check is "+
			"what keeps a forged notice out", len(scans), len(seen))
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "team@example.com") ||
		!strings.Contains(problems[0], "notification sender") {
		t.Errorf("problems = %v", problems)
	}
}

func TestTheFleetsOwnSignedMailIsNotALookalike(t *testing.T) {
	m := graph.Message{ID: "1", Subject: noticeSubject, From: "team@example.com",
		SelfSent: true, SelfVerified: true}
	if _, _, problems := collect([]graph.Message{m}); len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
}

const scheduledSubject = "Qualys: Scheduled Web Application Vulnerability Scan Notification"

func wasNotice(status string) string {
	return `<div>Scan Title : Example Shop Run #41</div>
<div>Scan Reference : was/5555555555555.66666666</div>
<div>Start Date : 11/08/2026 at 01:28:24 (GMT +0000)</div>
<div>Scan Status : ` + status + ` </div>`
}

func scheduledNotice(title, launch string) string {
	return `<p>Scheduled Task Information:<br /><br />Title: ` + title +
		`<br />Next Launch: ` + launch + `<br /></p>`
}

func TestTheScheduledNoticeOfAReportedRunIsClaimedForDeletion(t *testing.T) {
	msgs := []graph.Message{
		{ID: "res", From: "qualys@qualys.net", Subject: noticeSubject, BodyHTML: wasNotice("Finished : OK")},
		{ID: "sched", From: "qualys@qualys.net", Subject: scheduledSubject,
			BodyHTML: scheduledNotice("Example Shop", "11/08/2026 at 01:27:00 (GMT +0000)")},
		{ID: "lastweek", From: "qualys@qualys.net", Subject: scheduledSubject,
			BodyHTML: scheduledNotice("Example Shop", "11/01/2026 at 01:27:00 (GMT +0000)")},
		{ID: "otherapp", From: "qualys@qualys.net", Subject: scheduledSubject,
			BodyHTML: scheduledNotice("Example Portal", "11/08/2026 at 01:27:00 (GMT +0000)")},
		{ID: "fake", From: "team@example.com", Subject: scheduledSubject,
			BodyHTML: scheduledNotice("Example Shop", "11/08/2026 at 01:27:00 (GMT +0000)")},
	}
	_, seen, _ := collect(msgs)
	got := map[string]bool{}
	for _, s := range seen {
		got[s.ID] = s.Delete
	}
	if d, ok := got["res"]; !ok || d {
		t.Errorf("results notice: claimed=%v delete=%v - archived, not deleted", ok, d)
	}
	if d, ok := got["sched"]; !ok || !d {
		t.Errorf("the run's scheduled notice: claimed=%v delete=%v, want a delete claim", ok, d)
	}
	for _, id := range []string{"lastweek", "otherapp", "fake"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s was claimed and would be deleted", id)
		}
	}
}

func TestAFaultyRunKeepsItsScheduledNotice(t *testing.T) {
	msgs := []graph.Message{
		{ID: "res", From: "qualys@qualys.net", Subject: noticeSubject, BodyHTML: wasNotice("Time Limit Exceeded")},
		{ID: "sched", From: "qualys@qualys.net", Subject: scheduledSubject,
			BodyHTML: scheduledNotice("Example Shop", "11/08/2026 at 01:27:00 (GMT +0000)")},
	}
	_, seen, _ := collect(msgs)
	claimedResults := false
	for _, s := range seen {
		claimedResults = claimedResults || s.ID == "res"
		if s.ID == "sched" {
			t.Error("the scheduled notice of an incomplete run was claimed; it stays for a person")
		}
	}
	if !claimedResults {
		t.Error("the results notice should still be claimed")
	}
}
