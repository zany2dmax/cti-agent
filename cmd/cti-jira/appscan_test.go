package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/ticketref"
)

// appJira is a fake Jira for the application tickets: search by label,
// create (optionally refusing assignee/components), comment, attach,
// properties, user search. Synthetic keys and addresses throughout.
type appJira struct {
	mu        sync.Mutex
	open      map[string]map[string]any // label -> issue
	props     map[string]json.RawMessage
	creates   []map[string]any
	comments  map[string][]string
	refuseFix bool // refuse a create that carries an assignee or components
	users     []map[string]any
	next      int
}

func newAppJira(t *testing.T) (*appJira, *jira.Client) {
	t.Helper()
	fj := &appJira{open: map[string]map[string]any{}, props: map[string]json.RawMessage{},
		comments: map[string][]string{}, next: 100}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fj.mu.Lock()
		defer fj.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		p := r.URL.Path
		switch {
		case r.Method == http.MethodPost && p == "/rest/api/3/search/jql":
			var q struct {
				JQL string `json:"jql"`
			}
			_ = json.Unmarshal(body, &q)
			var out []map[string]any
			for label, is := range fj.open {
				if strings.Contains(q.JQL, `"`+label+`"`) {
					out = append(out, is)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": out, "isLast": true})
		case r.Method == http.MethodGet && p == "/rest/api/3/user/search":
			_ = json.NewEncoder(w).Encode(fj.users)
		case r.Method == http.MethodPost && p == "/rest/api/2/issue":
			var req struct {
				Fields map[string]any `json:"fields"`
			}
			_ = json.Unmarshal(body, &req)
			_, hasA := req.Fields["assignee"]
			_, hasC := req.Fields["components"]
			if fj.refuseFix && (hasA || hasC) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"errors":{"components":"Component name 'X' is not valid"}}`)
				return
			}
			fj.creates = append(fj.creates, req.Fields)
			fj.next++
			key := "SEC-" + itoa(fj.next)
			for _, l := range req.Fields["labels"].([]any) {
				if s := l.(string); strings.HasPrefix(s, "cti-appscan-") {
					fj.open[s] = map[string]any{"key": key, "fields": map[string]any{
						"summary": req.Fields["summary"],
						"status":  map[string]any{"name": "Open", "statusCategory": map[string]any{"key": "new"}}}}
				}
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": key, "id": "1"})
		case strings.Contains(p, "/properties/"):
			key := strings.Split(strings.TrimPrefix(p, "/rest/api/2/issue/"), "/")[0]
			if r.Method == http.MethodGet {
				v, ok := fj.props[key]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(`{"key":"x","value":` + string(v) + `}`))
				return
			}
			fj.props[key] = json.RawMessage(body)
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(p, "/comment"):
			key := strings.Split(strings.TrimPrefix(p, "/rest/api/2/issue/"), "/")[0]
			var c struct {
				Body string `json:"body"`
			}
			_ = json.Unmarshal(body, &c)
			fj.comments[key] = append(fj.comments[key], c.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case strings.HasSuffix(p, "/attachments"):
			_, _ = io.WriteString(w, `[]`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, p)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return fj, jira.New(srv.URL, "fleet@example.com", "token")
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func appTicket(findings ...appscan.TicketFinding) appscan.AppTicket {
	t := appscan.AppTicket{Key: "id:101", App: "Portal", AppID: "101", Owner: "lead@example.com",
		OwnerListed: true, Scanned: time.Date(2026, 10, 19, 2, 0, 0, 0, time.UTC),
		ScanLabel: "authenticated scan", Findings: findings}
	// A short fingerprint, as the builder makes.
	sum := sha256.Sum256([]byte(strings.Join(t.InstanceKeys(), "\n")))
	t.Hash = hex.EncodeToString(sum[:])[:16]
	return t
}

func xss(urls ...string) appscan.TicketFinding {
	f := appscan.TicketFinding{ID: "150001", Title: "Reflected XSS", Severity: 5, Status: "NEW",
		Remedy: &appscan.Remedy{Consequence: "Script runs in a victim's browser.",
			Diagnosis: "Input reflected unencoded.", Solution: "Encode output for its context.\n- HTML-encode\n- JS-encode"}}
	for _, u := range urls {
		f.Instances = append(f.Instances, appscan.Instance{URL: u, Param: "q"})
	}
	return f
}

func runApp(t *testing.T, c *jira.Client, forReal bool, tks ...appscan.AppTicket) map[string]ticketref.Ref {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "tickets.json")
	if err := os.WriteFile(in, appscan.TicketsFile{Tickets: tks}.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := filepath.Join(dir, "ref.json")
	if rc := doAppscanTickets(context.Background(), c, testCfg, in, forReal, time.Now(), ref); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	var got AppscanRefs
	if err := ticketref.Read(ref, &got); err != nil {
		t.Fatal(err)
	}
	return got.Apps
}

func TestAnApplicationTicketIsFiledAssignedAndCarriesTheFix(t *testing.T) {
	fj, c := newAppJira(t)
	fj.users = []map[string]any{{"accountId": "acc-1", "emailAddress": "lead@example.com",
		"active": true, "accountType": "atlassian"}}
	refs := runApp(t, c, true, appTicket(xss("https://app.example.com/a")))
	r := refs["id:101"]
	if r.Action != "created" || r.Assignee != "lead@example.com" {
		t.Fatalf("ref %+v", r)
	}
	if len(fj.creates) != 1 {
		t.Fatalf("creates %d", len(fj.creates))
	}
	f := fj.creates[0]
	if a, _ := f["assignee"].(map[string]any); a["accountId"] != "acc-1" {
		t.Errorf("not assigned: %v", f["assignee"])
	}
	desc := f["description"].(string)
	for _, want := range []string{"*How to fix it*", "Encode output for its context.", "* HTML-encode",
		"*Risk*", "{{https://app.example.com/a}} parameter {{q}}", "lead@example.com"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}
	if !strings.Contains(f["labels"].([]any)[2].(string), "cti-appscan-101") {
		t.Errorf("labels %v", f["labels"])
	}
}

func TestTheSameFindingsNextWeekPostNothingAndChangesComment(t *testing.T) {
	fj, c := newAppJira(t)
	week1 := appTicket(xss("https://app.example.com/a"))
	runApp(t, c, true, week1)
	if r := runApp(t, c, true, week1)["id:101"]; r.Action != "unchanged" {
		t.Errorf("same findings: %+v", r)
	}
	week2 := appTicket(xss("https://app.example.com/b"))
	r := runApp(t, c, true, week2)["id:101"]
	if r.Action != "commented" {
		t.Fatalf("changed findings: %+v", r)
	}
	cm := fj.comments[r.Key]
	if len(cm) != 1 || !strings.Contains(cm[0], "1 new place(s), 1 no longer detected") ||
		!strings.Contains(cm[0], "QID 150001: 1 place(s)") || !strings.Contains(cm[0], "{{https://app.example.com/b}}") {
		t.Errorf("comment %v", cm)
	}
	empty := appTicket()
	if r := runApp(t, c, true, empty)["id:101"]; r.Action != "resolved" {
		t.Errorf("nothing left: %+v", r)
	}
	if r := runApp(t, c, true, empty)["id:101"]; r.Action != "resolved" || len(fj.comments[r.Key]) != 2 {
		t.Errorf("told twice: %+v %d", r, len(fj.comments[r.Key]))
	}
}

func TestARefusedAssigneeStillFilesTheFindings(t *testing.T) {
	fj, c := newAppJira(t)
	fj.refuseFix = true
	fj.users = []map[string]any{{"accountId": "acc-1", "emailAddress": "lead@example.com", "active": true}}
	tk := appTicket(xss("https://app.example.com/a"))
	tk.Component = "Web Portal"
	r := runApp(t, c, true, tk)["id:101"]
	if r.Action != "created" || r.Assignee != "" || !strings.Contains(r.Note, "unassigned") {
		t.Errorf("ref %+v", r)
	}
}

func TestAnAmbiguousOwnerIsNotGuessed(t *testing.T) {
	fj, c := newAppJira(t)
	fj.users = []map[string]any{
		{"accountId": "a", "emailAddress": "", "active": true},
		{"accountId": "b", "emailAddress": "", "active": true},
	}
	r := runApp(t, c, true, appTicket(xss("u")))["id:101"]
	if r.Assignee != "" || len(fj.creates) != 1 || fj.creates[0]["assignee"] != nil {
		t.Errorf("assigned on a guess: %+v %v", r, fj.creates[0]["assignee"])
	}
}

func TestSkippedAndDryRunAppsWriteNothing(t *testing.T) {
	fj, c := newAppJira(t)
	sk := appTicket(xss("u"))
	sk.Skip = "the scan did not complete"
	other := appTicket(xss("u"))
	other.Key, other.App = "id:202", "Shop"
	refs := runApp(t, c, false, sk, other)
	if refs["id:101"].Action != "skipped" || refs["id:202"].Action != "would-create" {
		t.Errorf("refs %+v", refs)
	}
	if len(fj.creates) != 0 || len(fj.comments) != 0 || len(fj.props) != 0 {
		t.Error("a dry run or a skipped app wrote to Jira")
	}
}

func TestWikiTextCannotBecomeMarkup(t *testing.T) {
	got := wikiText("Use [link|http://evil] and *bold* {code} !https://evil.example/x.png!\n- item\nh1. heading\n-not a list\nbq. quote")
	for _, bad := range []string{"[link|", "*bold*", "{code}", "\nh1.", " !https", "\nbq."} {
		if strings.Contains(got, bad) {
			t.Errorf("markup survived %q in %q", bad, got)
		}
	}
	if !strings.Contains(got, "\n* item") {
		t.Errorf("list item lost: %q", got)
	}
}

func TestTheTicketStateFitsJirasPropertyLimit(t *testing.T) {
	f := appscan.TicketFinding{ID: "150001", Severity: 5}
	for i := 0; i < 5000; i++ {
		f.Instances = append(f.Instances, appscan.Instance{
			URL: "https://app.example.com/a/very/long/path/" + strings.Repeat("x", 200) + itoa(i), Param: "q"})
	}
	tk := appTicket(f)
	b, _ := json.Marshal(appscanState{Hash: tk.Hash, Keys: stateKeys(tk), PostedAt: time.Now()})
	if len(b) > 30000 {
		t.Errorf("state is %d bytes; Jira Cloud refuses an issue property over 32 KB", len(b))
	}
	if body := appscanBody(tk, time.Now()); len(body) > 32767 {
		t.Errorf("description %d chars, over Jira's limit", len(body))
	}
}

func TestATimeoutIsNotRetriedIntoADuplicate(t *testing.T) {
	if jira.IsBadRequest(context.DeadlineExceeded) {
		t.Error("a timeout read as a refusal - a retry could file a second ticket")
	}
	if !jira.IsBadRequest(&jira.StatusError{Code: 400, Err: context.Canceled}) {
		t.Error("a 400 not recognised")
	}
}

func TestAStagingTicketSaysTheFixGoesThroughDeployment(t *testing.T) {
	tk := appTicket(xss("https://site-stg.example.com/a"))
	tk.Covers = []string{"example.com"}
	body := appscanBody(tk, time.Now())
	if !strings.Contains(body, "*Stands in for:* {{example.com}}") || !strings.Contains(body, "then deploy") {
		t.Errorf("staging ticket does not say where the fix lands:\n%s", body)
	}
}
