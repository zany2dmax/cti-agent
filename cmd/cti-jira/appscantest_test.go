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
	"sync"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
)

// captureStdout runs f and returns what it printed to stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	defer func() { os.Stdout = old }()
	f()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

// recJira records every request; it answers just enough for a create and
// attachments. Any other call (search, comment, watcher, property) is
// recorded and fails the test that checks the record.
type recJira struct {
	mu       sync.Mutex
	reqs     []string // "METHOD path"
	creates  []map[string]any
	attached []string
}

func newRecJira(t *testing.T) (*recJira, *jira.Client) {
	t.Helper()
	rj := &recJira{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rj.mu.Lock()
		defer rj.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		rj.reqs = append(rj.reqs, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/issue":
			var req struct {
				Fields map[string]any `json:"fields"`
			}
			_ = json.Unmarshal(body, &req)
			rj.creates = append(rj.creates, req.Fields)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-501", "id": "1"})
		case strings.HasSuffix(r.URL.Path, "/attachments"):
			s := string(body)
			if i := strings.Index(s, `filename="`); i >= 0 {
				s = s[i+len(`filename="`):]
				rj.attached = append(rj.attached, s[:strings.Index(s, `"`)])
			}
			_, _ = io.WriteString(w, `[]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return rj, jira.New(srv.URL, "fleet@example.com", "token")
}

// onlyCreateAndAttach fails if anything but the create and its attachments
// reached Jira.
func (rj *recJira) onlyCreateAndAttach(t *testing.T) {
	t.Helper()
	for _, r := range rj.reqs {
		if r != "POST /rest/api/2/issue" && !strings.HasSuffix(r, "/attachments") {
			t.Errorf("unexpected Jira call: %s", r)
		}
	}
}

func ticketsFile(t *testing.T, tks ...appscan.AppTicket) string {
	t.Helper()
	in := filepath.Join(t.TempDir(), "tickets.json")
	if err := os.WriteFile(in, appscan.TicketsFile{Tickets: tks}.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestAttachPreviewNamesBothFilesOrSaysNoReport(t *testing.T) {
	with := attachPreview(true, "qualys-was-report-2026-10-24.zip", []byte("PKzip"), "appscan-2026-10-24.txt", []byte("text"))
	for _, want := range []string{"----- would attach appscan-2026-10-24.txt (4 bytes)",
		"----- would attach qualys-was-report-2026-10-24.zip (5 bytes)"} {
		if !strings.Contains(with, want) {
			t.Errorf("preview lacks %q:\n%s", want, with)
		}
	}
	without := attachPreview(false, "-report-x.zip", nil, "appscan-2026-10-24.txt", []byte("text"))
	if !strings.Contains(without, "would attach appscan-2026-10-24.txt") ||
		!strings.Contains(without, "----- no scanner report to attach") ||
		strings.Contains(without, ".zip") {
		t.Errorf("preview without a report:\n%s", without)
	}
}

func TestAppscanTicketsPreviewPrintsWouldAttachLines(t *testing.T) {
	_, c := newAppJira(t)
	in := ticketsFile(t, appTicket(xss("https://app.example.com/a")))
	out := captureStdout(t, func() {
		if rc := doAppscanTickets(context.Background(), c, testCfg, in, false, time.Now(), "", writeReports(t, "id:101")); rc != exitOK {
			t.Errorf("rc %d", rc)
		}
	})
	if !strings.Contains(out, "----- would attach appscan-") || !strings.Contains(out, "-report-") ||
		strings.Contains(out, "no scanner report to attach") {
		t.Errorf("preview with a report:\n%s", out)
	}
	out = captureStdout(t, func() {
		if rc := doAppscanTickets(context.Background(), c, testCfg, in, false, time.Now(), "", ""); rc != exitOK {
			t.Errorf("rc %d", rc)
		}
	})
	if !strings.Contains(out, "----- would attach appscan-") || !strings.Contains(out, "----- no scanner report to attach") ||
		strings.Contains(out, ".zip") {
		t.Errorf("preview without a report:\n%s", out)
	}
}

func TestAppscanTestPreviewCreatesNothing(t *testing.T) {
	rj, c := newRecJira(t)
	in := ticketsFile(t, appTicket(xss("https://app.example.com/a")))
	out := captureStdout(t, func() {
		if rc := doAppscanTest(context.Background(), c, testCfg, in, "101", writeReports(t, "id:101"), false, time.Now()); rc != exitOK {
			t.Errorf("rc %d", rc)
		}
	})
	if len(rj.reqs) != 0 {
		t.Errorf("preview called Jira: %v", rj.reqs)
	}
	for _, want := range []string{"[TEST] AppSec: Portal", "labels: cti-agent-test", "----- would attach appscan-", "-report-"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview lacks %q:\n%s", want, out)
		}
	}
}

func TestAppscanTestForRealFilesOneBareTicketWithReport(t *testing.T) {
	rj, c := newRecJira(t)
	in := ticketsFile(t, appTicket(xss("https://app.example.com/a")))
	if rc := doAppscanTest(context.Background(), c, testCfg, in, "101", writeReports(t, "id:101"), true, time.Now()); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	if len(rj.creates) != 1 {
		t.Fatalf("creates %d", len(rj.creates))
	}
	f := rj.creates[0]
	if s, _ := f["summary"].(string); !strings.HasPrefix(s, "[TEST] AppSec: Portal") {
		t.Errorf("summary %q", s)
	}
	if l, _ := json.Marshal(f["labels"]); string(l) != `["cti-agent-test"]` {
		t.Errorf("labels %s", l)
	}
	for _, k := range []string{"assignee", "components"} {
		if _, ok := f[k]; ok {
			t.Errorf("test ticket carries %s", k)
		}
	}
	rj.onlyCreateAndAttach(t)
	if len(rj.attached) != 2 {
		t.Errorf("attachments %v, want 2", rj.attached)
	}
}

func TestAppscanTestForRealWithoutReportAttachesOneFile(t *testing.T) {
	rj, c := newRecJira(t)
	in := ticketsFile(t, appTicket(xss("https://app.example.com/a")))
	if rc := doAppscanTest(context.Background(), c, testCfg, in, "101", "", true, time.Now()); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	if len(rj.creates) != 1 || len(rj.attached) != 1 || !strings.HasPrefix(rj.attached[0], "appscan-") {
		t.Errorf("creates %d attached %v", len(rj.creates), rj.attached)
	}
	rj.onlyCreateAndAttach(t)
}

func TestAppscanTestRefusesUnknownAndSkippedApps(t *testing.T) {
	rj, c := newRecJira(t)
	sk := appTicket(xss("u"))
	sk.Skip = "the scan did not complete"
	in := ticketsFile(t, sk)
	for _, id := range []string{"101", "999"} {
		for _, real := range []bool{false, true} {
			if rc := doAppscanTest(context.Background(), c, testCfg, in, id, "", real, time.Now()); rc == exitOK {
				t.Errorf("id %s forReal=%v: rc OK, want refusal", id, real)
			}
		}
	}
	if len(rj.reqs) != 0 {
		t.Errorf("a refused test called Jira: %v", rj.reqs)
	}
}

func TestAppscanTestRefusesWhenTheWriteGateIsClosed(t *testing.T) {
	rj, c := newRecJira(t)
	in := ticketsFile(t, appTicket(xss("u")))
	for _, allow := range []string{"", "OTHER"} {
		cfg := config.Config{JiraProjectKey: "SEC", JiraAllowCreate: allow}
		if rc := doAppscanTest(context.Background(), c, cfg, in, "101", "", true, time.Now()); rc == exitOK {
			t.Errorf("allow %q: rc OK, want refusal", allow)
		}
	}
	if len(rj.reqs) != 0 {
		t.Errorf("closed gate still called Jira: %v", rj.reqs)
	}
}
