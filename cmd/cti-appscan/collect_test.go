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
