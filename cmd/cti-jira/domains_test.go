package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
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

// IT tracks the weekly lock-down in INF while CVE and AppSec tickets stay in
// CR, so the domains lane searches, gates and files by its own project.
func TestTheDomainsLaneSearchesItsOwnProject(t *testing.T) {
	var jql []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		jql = append(jql, string(body))
		_ = json.NewEncoder(w).Encode(map[string]any{"issues": []any{}, "isLast": true})
	}))
	defer srv.Close()
	c := jira.New(srv.URL, "fleet@example.com", "token")

	work := actionsFile(domains.Action{Domain: "a.example", Profile: "4/5. no mail", Type: "TXT",
		Host: "@", Set: "v=spf1 -all"})
	raw, _ := json.Marshal(work)
	path := filepath.Join(t.TempDir(), "actions.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{JiraProjectKey: "CR", JiraDomainsProject: "INF", JiraAllowCreate: "CR,INF"}
	if rc := doDomainsActions(context.Background(), c, cfg, path, false, time.Now(), ""); rc != exitOK {
		t.Fatalf("exit %d", rc)
	}
	if len(jql) != 1 || !strings.Contains(jql[0], `project = \"INF\"`) {
		t.Errorf("search did not target INF: %v", jql)
	}
}

func TestTheDomainsProjectFollowsTheMainOneUnlessSet(t *testing.T) {
	cfg := config.Config{JiraProjectKey: "CR", JiraIssueType: "IT Support"}
	if cfg.DomainsProject() != "CR" || cfg.DomainsIssueType() != "IT Support" {
		t.Errorf("unset must follow CR: %q %q", cfg.DomainsProject(), cfg.DomainsIssueType())
	}
	cfg.JiraDomainsProject, cfg.JiraDomainsIssueType = " INF ", "Task"
	if cfg.DomainsProject() != "INF" || cfg.DomainsIssueType() != "Task" {
		t.Errorf("set must win, trimmed: %q %q", cfg.DomainsProject(), cfg.DomainsIssueType())
	}
}

func TestADomainsTicketInAnotherProjectIsStillListedForTheDigest(t *testing.T) {
	lock := ticket("INF-590", "CVE-0000-0", "indeterminate")
	lock["fields"].(map[string]any)["labels"] = []string{"cti-agent", domainsLabel}
	fj, c := newFakeJira(t, lock)
	_ = fj
	cfg := config.Config{JiraProjectKey: "CR", JiraDomainsProject: "INF", JiraAllowCreate: "CR"}
	refs := followUp(context.Background(), c, cfg, (&scanner{}).look, map[string]bool{}, time.Now(), false)
	if r, ok := refs[lockdownRefKey]; !ok || r.Key != "INF-590" {
		t.Errorf("lock-down ticket missing from the digest refs: %+v", refs)
	}
}
