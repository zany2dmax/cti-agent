package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/domains"
)

// The report has to say which ticket IT is working from, and what happened to
// it this week. --ref-out is how that reaches cti-domains --stamp-ticket.
func TestDomainsRefOutNamesTheTicketAndWhatHappened(t *testing.T) {
	lock := map[string]any{
		"key": "SEC-50",
		"fields": map[string]any{
			"summary": "Domain DNS lock-down",
			"status": map[string]any{"name": "Waiting for support",
				"statusCategory": map[string]any{"key": "indeterminate"}},
			"labels": []string{"cti-agent", domainsLabel},
		},
	}
	dir := t.TempDir()
	actions := filepath.Join(dir, "actions.json")
	work := actionsFile(domains.Action{Domain: "a.example", Profile: "4/5. no mail", Type: "TXT",
		Host: "@", Set: "v=spf1 -all", Why: "sends no mail"})
	if err := os.WriteFile(actions, work.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		forReal bool
		want    string
	}{{false, "would-comment"}, {true, "commented"}} {
		_, c := newFakeJira(t, lock)
		ref := filepath.Join(dir, "ref.json")
		_ = os.Remove(ref)
		if rc := doDomainsActions(context.Background(), c, testCfg, actions, tc.forReal, time.Now(), ref); rc != exitOK {
			t.Fatalf("forReal=%v: rc %d", tc.forReal, rc)
		}
		got, err := domains.ReadTicketRef(ref)
		if err != nil {
			t.Fatalf("forReal=%v: no ref written: %v", tc.forReal, err)
		}
		if got.Action != tc.want || got.Key != "SEC-50" || got.Status != "Waiting for support" {
			t.Errorf("forReal=%v: ref = %+v", tc.forReal, got)
		}
		if !strings.HasSuffix(got.URL, "/browse/SEC-50") {
			t.Errorf("forReal=%v: ref URL %q", tc.forReal, got.URL)
		}
		// The fake server is plain http, so the email gets the key but not
		// the link: only https browse links are put in a report.
		if line, url := domains.TicketLine(got); url != "" || !strings.Contains(line, "SEC-50") {
			t.Errorf("forReal=%v: line %q url %q", tc.forReal, line, url)
		}
	}
}
