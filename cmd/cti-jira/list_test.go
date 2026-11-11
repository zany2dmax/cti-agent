package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
)

func TestTicketKind(t *testing.T) {
	cases := map[string][]string{
		"CVE":       {"cti-agent", "cti-cve-2026-1234"},
		"AppSec":    {"cti-agent", "cti-appscan", "cti-app-ex1"},
		"lock-down": {"cti-agent", "cti-domains-lockdown"},
		"test":      {"cti-agent-test", "cti-appscan"},
		"other":     {"cti-agent"},
	}
	for want, labels := range cases {
		if got := ticketKind(labels); got != want {
			t.Errorf("%v: got %s want %s", labels, got, want)
		}
	}
}

func TestListJQLIsScopedAndOpenOnlyUnlessAll(t *testing.T) {
	open := listJQL("EX", false)
	if !strings.Contains(open, `project = "EX"`) || !strings.Contains(open, "statusCategory != Done") ||
		!strings.Contains(open, `"cti-agent-test"`) {
		t.Errorf("open JQL: %s", open)
	}
	if strings.Contains(listJQL("EX", true), "statusCategory") {
		t.Error("--all must not filter on status")
	}
}

func listServer(t *testing.T, jql *string, methods *[]string) *jira.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*methods = append(*methods, r.Method+" "+r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		var req struct {
			JQL string `json:"jql"`
		}
		_ = json.Unmarshal(b, &req)
		*jql = req.JQL
		_, _ = io.WriteString(w, `{"isLast":true,"issues":[
		 {"key":"EX-1","fields":{"summary":"CVE-2026-1 on host-a\u001b[31m RED","status":{"name":"To Do","statusCategory":{"key":"new"}},
		  "labels":["cti-agent","cti-cve-2026-1"],"created":"2026-11-01T10:00:00.000+0000","assignee":{"displayName":"Pat Example"}}},
		 {"key":"EX-2","fields":{"summary":"[TEST] app","status":{"name":"Done","statusCategory":{"key":"done"}},
		  "labels":["cti-agent-test"],"created":"2026-11-09T10:00:00.000+0000","assignee":null}}]}`)
	}))
	t.Cleanup(srv.Close)
	return jira.New(srv.URL, "fleet@example.com", "token")
}

func TestDoListTableReadsOnlyAndSanitises(t *testing.T) {
	var jql string
	var calls []string
	c := listServer(t, &jql, &calls)
	var out bytes.Buffer
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	if rc := doList(context.Background(), c, config.Config{JiraProjectKey: "EX"}, false, false, &out, now); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	if len(calls) != 1 || calls[0] != "POST /rest/api/3/search/jql" {
		t.Errorf("calls: %v", calls)
	}
	if !strings.Contains(jql, "statusCategory != Done") {
		t.Errorf("jql: %s", jql)
	}
	s := out.String()
	for _, want := range []string{"EX-1", "10d", "Pat Example", "CVE", "unassigned", "test"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.ContainsRune(s, 0x1b) {
		t.Errorf("escape character reached the output: %q", s)
	}
}

func TestDoListJSONAndAll(t *testing.T) {
	var jql string
	var calls []string
	c := listServer(t, &jql, &calls)
	var out bytes.Buffer
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	if rc := doList(context.Background(), c, config.Config{JiraProjectKey: "EX"}, true, true, &out, now); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	if strings.Contains(jql, "statusCategory") {
		t.Errorf("--all jql: %s", jql)
	}
	var rows []listRow
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("json: %v %s", err, out.String())
	}
	if rows[0].Kind != "CVE" || rows[1].Kind != "test" || !rows[1].Done || rows[1].Assignee != "unassigned" || rows[1].AgeDays != 2 {
		t.Errorf("rows: %+v", rows)
	}
}

func TestScannerForHonoursLookupProviderNone(t *testing.T) {
	fill, err := scannerFor(context.Background(), config.Config{LookupProvider: "none"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := fill(context.Background(), "CVE-2026-0001")
	if err != nil || r.Status != "UNKNOWN" {
		t.Errorf("%+v %v", r, err)
	}
	if _, err := scannerFor(context.Background(), config.Config{LookupProvider: "bogus"}); err == nil {
		t.Error("unsupported LOOKUP_PROVIDER must error")
	}
}
