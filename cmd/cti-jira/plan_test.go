package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/jira"
)

func issueIn(category string) jira.Issue {
	var i jira.Issue
	i.Key = "SEC-30"
	i.Fields.Status.StatusCategory.Key = category
	return i
}

func stateOf(hosts ...string) *jira.ExposureState {
	st := jira.StateFrom(jira.Finding{CVE: "CVE-2026-3030", Hosts: hosts}, "SEC-30",
		time.Now().Add(-24*time.Hour))
	return &st
}

func TestThePreviewSaysWhetherAnybodyGetsAComment(t *testing.T) {
	now := time.Now()
	noted := stateOf("host-a")
	noted.ClosedButDetectedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		issue    jira.Issue
		prev     *jira.ExposureState
		finding  jira.Finding
		kind     updateKind
		says     string
		comments bool
	}{
		{"first look", issueIn("indeterminate"), nil,
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a"}},
			planRecordOnly, "no stored state yet", false},
		{"unchanged", issueIn("indeterminate"), stateOf("host-a", "host-b"),
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a", "host-b"}},
			planRecordOnly, "no change since the last report (2 host(s))", false},
		{"shrank", issueIn("indeterminate"), stateOf("host-a", "host-b", "host-c"),
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a"}},
			planRecordOnly, "shrank 3 -> 1", false},
		{"grew", issueIn("indeterminate"), stateOf("host-a"),
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a", "host-b", "host-c"}},
			planComment, "WOULD COMMENT: grew 1 -> 3 host(s), 2 new host(s)", true},
		{"new QID", issueIn("indeterminate"), stateOf("host-a"),
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a"}, QIDs: []string{"100001"}},
			planComment, "1 new QID(s)", true},
		{"fixed", issueIn("indeterminate"), stateOf("host-a", "host-b"),
			jira.Finding{CVE: "CVE-2026-3030"},
			planComment, "WOULD COMMENT: no detections remain (was 2)", true},
		{"closed, first time", issueIn("done"), stateOf("host-a"),
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a"}},
			planClosedComment, "WOULD COMMENT ONCE: closed", true},
		{"closed, already said", issueIn("done"), noted,
			jira.Finding{CVE: "CVE-2026-3030", Hosts: []string{"host-a"}},
			planClosedNoted, "already noted on 2026-10-01, no comment", false},
	} {
		p := planUpdate(tc.issue, tc.prev, tc.finding, now)
		if p.kind != tc.kind {
			t.Errorf("%s: kind = %d, want %d", tc.name, p.kind, tc.kind)
		}
		got := p.describe(tc.finding)
		if !strings.Contains(got, tc.says) {
			t.Errorf("%s: preview = %q, want it to contain %q", tc.name, got, tc.says)
		}
		// The words a reader scans for. A preview that hedged here would
		// leave "is IT hearing about this?" to be worked out by hand.
		if strings.Contains(got, "WOULD COMMENT") != tc.comments {
			t.Errorf("%s: preview %q gets 'would comment' wrong", tc.name, got)
		}
	}
}

func TestThePreviewAndTheRealRunAgree(t *testing.T) {
	// Run the same ticket twice: a dry run that says "WOULD COMMENT", then the
	// real run, which must post exactly one comment. And the reverse for a
	// ticket the preview calls unchanged.
	for _, tc := range []struct {
		name    string
		before  []string
		after   []string
		comment bool
	}{
		{"grew", []string{"host-a"}, []string{"host-a", "host-b"}, true},
		{"unchanged", []string{"host-a"}, []string{"host-a"}, false},
	} {
		fj, c := newFakeJira(t)
		previously(fj, "SEC-31", "CVE-2026-3131", tc.before...)
		issue := issueIn("indeterminate")
		issue.Key = "SEC-31"
		f := jira.Finding{CVE: "CVE-2026-3131", Hosts: tc.after}

		preview := previewUpdate(context.Background(), c, issue, f, time.Now())
		if len(fj.comments["SEC-31"]) != 0 || fj.propPuts["SEC-31"] != 0 {
			t.Fatalf("%s: the preview wrote to Jira", tc.name)
		}
		csv, _ := jira.HostCSV(f)
		updateExisting(context.Background(), c, issue, f, csv, time.Now())

		said := strings.Contains(preview, "WOULD COMMENT")
		did := len(fj.comments["SEC-31"]) == 1
		if said != tc.comment || did != tc.comment {
			t.Errorf("%s: preview %q (would comment: %v), real run commented: %v",
				tc.name, preview, said, did)
		}
	}
}
