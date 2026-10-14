package main

import (
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/domains"
	"github.com/zany2dmax/cti-agent/internal/jira"
)

func actionsFile(a ...domains.Action) domains.ActionsFile {
	return domains.NewActionsFile(time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC), a)
}

func TestOneLockDownTicketAtATime(t *testing.T) {
	work := actionsFile(domains.Action{Domain: "a.example", Profile: "4/5. no mail", Type: "TXT",
		Host: "@", Set: "v=spf1 -all", Why: "sends no mail"})
	none := actionsFile()
	open := &jira.Issue{Key: "SEC-7"}
	posted := domainsState{Hash: work.Hash, PostedAt: time.Now()}

	for _, c := range []struct {
		name string
		open *jira.Issue
		prev domainsState
		af   domains.ActionsFile
		want domainsPlan
	}{
		{"nothing to do, nothing open", nil, domainsState{}, none, domainsNothing},
		{"work and nothing open: file one", nil, domainsState{}, work, domainsCreate},
		{"same list already posted: stay quiet", open, posted, work, domainsNothing},
		{"list changed: comment", open, domainsState{Hash: "old"}, work, domainsComment},
		{"all done: say so once", open, posted, none, domainsDone},
		{"all done and already said", open, domainsState{Resolved: true}, none, domainsNothing},
	} {
		if got, _ := planDomains(c.open, c.prev, c.af); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestTheTicketBodySeparatesExactFromReview(t *testing.T) {
	af := actionsFile(
		domains.Action{Domain: "a.example", Profile: "4/5. no mail", Type: "MX", Host: "@",
			Set: "0 .", Replace: "mx1.example.test", Why: "receives no mail"},
		domains.Action{Domain: "b.example", Profile: "1. active mail domain", Type: "TXT", Host: "@",
			Replace: "v=spf1 include:x -all", Why: "SPF is broken - fix it first"},
	)
	body := domainsBody(af, time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC))
	for _, want := range []string{
		"h3. Exact changes (1)", "h3. To review (1)",
		"*a.example* (4/5. no mail)",
		"MX {{@}}: replace {{mx1.example.test}} with {{0 .}}",
		"Before setting a null MX",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if strings.Index(body, "h3. Exact") > strings.Index(body, "h3. To review") {
		t.Error("exact changes must come first")
	}
}

func TestWikiEscapeKeepsValuesLiteral(t *testing.T) {
	if got := wikiEscape("v=DKIM1; p={abc}|[x]"); got != `v=DKIM1; p=\{abc\}\|\[x\]` {
		t.Errorf("wikiEscape = %q", got)
	}
}
