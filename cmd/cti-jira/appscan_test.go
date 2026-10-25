package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
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
	watchers  map[string][]string // issue key -> accountIds posted
	failWatch bool                // answer every watchers POST with 403
	attached  map[string][]string // issue key -> attachment file names

	done         map[string]map[string]any // label -> closed issue, for the Done search
	doneSearches int                       // how many Done-category searches were asked
	failDone     bool                      // answer the Done search with a 500
	links        []map[string]any          // issueLink bodies posted
	failLink     bool                      // answer an issueLink POST with 403
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
			if strings.Contains(q.JQL, "statusCategory = Done") {
				fj.doneSearches++
				if fj.failDone {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				for label, is := range fj.done {
					if strings.Contains(q.JQL, `"`+label+`"`) {
						out = append(out, is)
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"issues": out, "isLast": true})
				return
			}
			for label, is := range fj.open {
				if strings.Contains(q.JQL, `"`+label+`"`) {
					out = append(out, is)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": out, "isLast": true})
		case r.Method == http.MethodPost && p == "/rest/api/2/issueLink":
			if fj.failLink {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var l map[string]any
			_ = json.Unmarshal(body, &l)
			fj.links = append(fj.links, l)
			w.WriteHeader(http.StatusCreated)
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
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/watchers"):
			if fj.failWatch {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			key := strings.Split(strings.TrimPrefix(p, "/rest/api/2/issue/"), "/")[0]
			var id string
			_ = json.Unmarshal(body, &id)
			if fj.watchers == nil {
				fj.watchers = map[string][]string{}
			}
			fj.watchers[key] = append(fj.watchers[key], id)
			w.WriteHeader(http.StatusNoContent)
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
			key := strings.Split(strings.TrimPrefix(p, "/rest/api/2/issue/"), "/")[0]
			if m := regexp.MustCompile(`filename="([^"]+)"`).FindSubmatch(body); m != nil {
				if fj.attached == nil {
					fj.attached = map[string][]string{}
				}
				fj.attached[key] = append(fj.attached[key], string(m[1]))
			}
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
	if rc := doAppscanTickets(context.Background(), c, testCfg, in, forReal, time.Now(), ref, ""); rc != exitOK {
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

func watchUsers() []map[string]any {
	return []map[string]any{
		{"accountId": "acc-1", "emailAddress": "lead@example.com", "active": true, "accountType": "atlassian"},
		{"accountId": "acc-2", "emailAddress": "qa@example.com", "active": true, "accountType": "atlassian"},
		{"accountId": "acc-3", "emailAddress": "pm@example.com", "active": true, "accountType": "atlassian"},
	}
}

func TestWatchersAreAddedOnCreateAndMissingOnesSkipped(t *testing.T) {
	fj, c := newAppJira(t)
	fj.users = watchUsers()
	tk := appTicket(xss("https://app.example.com/a"))
	tk.Watchers = []string{"qa@example.com", "ghost@example.com", "pm@example.com"}
	r := runApp(t, c, true, tk)["id:101"]
	if r.Action != "created" {
		t.Fatalf("ref %+v", r)
	}
	got := fj.watchers[r.Key]
	if len(got) != 2 || got[0] != "acc-2" || got[1] != "acc-3" {
		t.Errorf("watchers %v (the unknown one must be skipped, the ticket still filed)", got)
	}
}

func TestAFailingWatcherCallDoesNotChangeTheOutcome(t *testing.T) {
	fj, c := newAppJira(t)
	fj.users = watchUsers()
	fj.failWatch = true
	tk := appTicket(xss("https://app.example.com/a"))
	tk.Watchers = []string{"qa@example.com"}
	r := runApp(t, c, true, tk)["id:101"]
	if r.Action != "created" || r.Key == "" || len(fj.watchers) != 0 {
		t.Errorf("ref %+v watchers %v", r, fj.watchers)
	}
}

func TestWatchersAreReAddedOnAComment(t *testing.T) {
	fj, c := newAppJira(t)
	fj.users = watchUsers()
	week1 := appTicket(xss("https://app.example.com/a"))
	week1.Watchers = []string{"qa@example.com"}
	key := runApp(t, c, true, week1)["id:101"].Key
	week2 := appTicket(xss("https://app.example.com/b"))
	week2.Watchers = []string{"qa@example.com", "pm@example.com"}
	if r := runApp(t, c, true, week2)["id:101"]; r.Action != "commented" {
		t.Fatalf("ref %+v", r)
	}
	got := fj.watchers[key]
	if len(got) != 3 || got[0] != "acc-2" || got[1] != "acc-2" || got[2] != "acc-3" {
		t.Errorf("watchers %v", got)
	}
}

func TestDryRunAndSkippedAppsAddNoWatchers(t *testing.T) {
	fj, c := newAppJira(t)
	fj.users = watchUsers()
	sk := appTicket(xss("u"))
	sk.Skip = "the scan did not complete"
	sk.Watchers = []string{"qa@example.com"}
	other := appTicket(xss("u"))
	other.Key, other.App = "id:202", "Shop"
	other.Watchers = []string{"pm@example.com"}
	runApp(t, c, false, sk, other)
	if len(fj.watchers) != 0 {
		t.Errorf("watchers added on a dry run: %v", fj.watchers)
	}
	runApp(t, c, true, sk)
	if len(fj.watchers) != 0 {
		t.Errorf("watchers added for a skipped app: %v", fj.watchers)
	}
}

// closeApp registers a closed ticket for the application (label cti-appscan-101)
// whose recorded state holds the given findings.
func (fj *appJira) closeApp(label, key string, was ...appscan.AppTicket) {
	if fj.done == nil {
		fj.done = map[string]map[string]any{}
	}
	fj.done[label] = map[string]any{"key": key, "fields": map[string]any{
		"summary": "old",
		"status":  map[string]any{"name": "Done", "statusCategory": map[string]any{"key": "done"}}}}
	var keys []string
	for _, t := range was {
		keys = append(keys, stateKeys(t)...)
	}
	b, _ := json.Marshal(appscanState{Hash: "old", Keys: keys, Resolved: true})
	fj.props[key] = b
}

func TestARecurringTicketNamesAndLinksTheClosedOne(t *testing.T) {
	fj, c := newAppJira(t)
	fj.closeApp("cti-appscan-101", "SEC-12", appTicket(xss("https://app.example.com/a"), xss("https://app.example.com/old")))
	refs := runApp(t, c, true, appTicket(xss("https://app.example.com/a", "https://app.example.com/new")))
	if refs["id:101"].Action != "created" || len(fj.creates) != 1 {
		t.Fatalf("refs %+v creates %d", refs, len(fj.creates))
	}
	desc := fj.creates[0]["description"].(string)
	if !strings.Contains(desc, "*Recurring:* this application's previous ticket, SEC-12, is Done.") ||
		!strings.Contains(desc, " 1 of the findings below were on it") {
		t.Errorf("description:\n%s", desc)
	}
	if len(fj.links) != 1 {
		t.Fatalf("links %v", fj.links)
	}
	l := fj.links[0]
	in, out := l["inwardIssue"].(map[string]any), l["outwardIssue"].(map[string]any)
	if l["type"].(map[string]any)["name"] != "Relates" || in["key"] != refs["id:101"].Key || out["key"] != "SEC-12" {
		t.Errorf("link %v", l)
	}
}

func TestARecurringTicketCountsEveryOverlap(t *testing.T) {
	fj, c := newAppJira(t)
	both := appTicket(xss("https://app.example.com/a", "https://app.example.com/b"))
	fj.closeApp("cti-appscan-101", "SEC-12", both)
	runApp(t, c, true, both)
	if d := fj.creates[0]["description"].(string); !strings.Contains(d, " 2 of the findings below were on it") {
		t.Errorf("description:\n%s", d)
	}
}

func TestAPriorWithNoSharedFindingsStillLinksWithoutACount(t *testing.T) {
	fj, c := newAppJira(t)
	fj.closeApp("cti-appscan-101", "SEC-12", appTicket(xss("https://app.example.com/old")))
	runApp(t, c, true, appTicket(xss("https://app.example.com/new")))
	d := fj.creates[0]["description"].(string)
	if !strings.Contains(d, "SEC-12") || strings.Contains(d, "were on it") || len(fj.links) != 1 {
		t.Errorf("links %d description:\n%s", len(fj.links), d)
	}
}

func TestNoPriorMeansNoNoteAndNoLink(t *testing.T) {
	fj, c := newAppJira(t)
	runApp(t, c, true, appTicket(xss("https://app.example.com/a")))
	if d := fj.creates[0]["description"].(string); strings.Contains(d, "Recurring") || len(fj.links) != 0 {
		t.Errorf("links %d description:\n%s", len(fj.links), d)
	}
}

func TestAFailedPriorSearchStillFilesTheTicketWithoutALink(t *testing.T) {
	fj, c := newAppJira(t)
	fj.failDone = true
	refs := runApp(t, c, true, appTicket(xss("https://app.example.com/a")))
	if refs["id:101"].Action != "created" || len(fj.creates) != 1 || len(fj.links) != 0 ||
		strings.Contains(fj.creates[0]["description"].(string), "Recurring") {
		t.Errorf("refs %+v creates %d links %d", refs, len(fj.creates), len(fj.links))
	}
}

func TestARefusedLinkLeavesTheTicketCreated(t *testing.T) {
	fj, c := newAppJira(t)
	fj.closeApp("cti-appscan-101", "SEC-12", appTicket(xss("https://app.example.com/a")))
	fj.failLink = true
	refs := runApp(t, c, true, appTicket(xss("https://app.example.com/a")))
	if refs["id:101"].Action != "created" || len(fj.creates) != 1 || len(fj.links) != 0 {
		t.Errorf("refs %+v creates %d links %d", refs, len(fj.creates), len(fj.links))
	}
}

func TestPreviewShowsTheLinkAndCreatesNothing(t *testing.T) {
	fj, c := newAppJira(t)
	fj.closeApp("cti-appscan-101", "SEC-12", appTicket(xss("https://app.example.com/a")))
	in := ticketsFile(t, appTicket(xss("https://app.example.com/a")))
	out := captureStdout(t, func() {
		if rc := doAppscanTickets(context.Background(), c, testCfg, in, false, time.Now(), "", ""); rc != exitOK {
			t.Errorf("rc %d", rc)
		}
	})
	if !strings.Contains(out, "*Recurring:* this application's previous ticket, SEC-12") ||
		!strings.Contains(out, "----- would link to SEC-12 (Done)") {
		t.Errorf("preview:\n%s", out)
	}
	if len(fj.creates) != 0 || len(fj.links) != 0 {
		t.Errorf("preview wrote: creates %d links %d", len(fj.creates), len(fj.links))
	}
}

func TestACommentRunNeverLooksForAPrior(t *testing.T) {
	fj, c := newAppJira(t)
	runApp(t, c, true, appTicket(xss("https://app.example.com/a")))
	before := fj.doneSearches
	fj.closeApp("cti-appscan-101", "SEC-12")
	if r := runApp(t, c, true, appTicket(xss("https://app.example.com/b")))["id:101"]; r.Action != "commented" {
		t.Fatalf("ref %+v", r)
	}
	if fj.doneSearches != before || len(fj.links) != 0 {
		t.Errorf("done searches %d -> %d, links %d", before, fj.doneSearches, len(fj.links))
	}
}

func withEvidence(proof string) appscan.TicketFinding {
	f := xss("https://app.example.com/a/b/", "https://app.example.com/c/")
	f.Instances[0].Evidence = &appscan.Evidence{Method: "GET", Link: "https://app.example.com/a/b/",
		Payload: "<x>", AccessPath: []string{"https://app.example.com/", "https://app.example.com/a/"},
		Proof: proof}
	f.Instances[1].Evidence = &appscan.Evidence{Method: "POST", Link: "https://app.example.com/c/", Proof: "second"}
	return f
}

func TestTheTicketShowsHowTheScannerFoundIt(t *testing.T) {
	body := appscanBody(appTicket(withEvidence("Vulnerable blank target found")), time.Now())
	for _, want := range []string{"*How the scanner found it*", "{{GET https://app.example.com/a/b/}}",
		"Reached from:", "{noformat}", "Vulnerable blank target found"} {
		if !strings.Contains(body, want) {
			t.Errorf("ticket body lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "POST https://app.example.com/c/") {
		t.Error("the ticket shows more than one instance's evidence; the rest belongs in the attachment")
	}
}

func TestAProofCannotEndItsNoformatBlockEarly(t *testing.T) {
	blk := findingBlock(withEvidence("before {noformat}x after {NOFORMAT:y} end"))
	if n := strings.Count(strings.ToLower(blk), "{noformat"); n != 2 {
		t.Errorf("%d {noformat delimiters; want exactly the block's two:\n%s", n, blk)
	}
	if !strings.Contains(blk, "(noformat}x") {
		t.Errorf("the proof text was lost rather than defused:\n%s", blk)
	}
}

func TestTheAttachmentCarriesEveryInstancesEvidence(t *testing.T) {
	txt := appscanFullText(appTicket(withEvidence("p")), time.Now())
	for _, want := range []string{"request: GET https://app.example.com/a/b/", "request: POST https://app.example.com/c/"} {
		if !strings.Contains(txt, want) {
			t.Errorf("attachment lacks %q:\n%s", want, txt)
		}
	}
}

func TestEvidenceDoesNotChangeTheFingerprint(t *testing.T) {
	a := appTicket(xss("https://app.example.com/a/b/", "https://app.example.com/c/"))
	b := appTicket(withEvidence("some proof"))
	if a.Hash != b.Hash {
		t.Errorf("hash changed with evidence: %s vs %s", a.Hash, b.Hash)
	}
	if strings.Join(a.InstanceKeys(), "|") != strings.Join(b.InstanceKeys(), "|") {
		t.Error("InstanceKeys changed with evidence")
	}
}

// The attachment carries evidence for at most maxEvidencePerFinding places
// per finding, and URL secrets are scrubbed in what it lists.
func TestAttachmentEvidenceIsCappedAndURLsScrubbed(t *testing.T) {
	var ins []appscan.Instance
	for i := 0; i < maxEvidencePerFinding+5; i++ {
		ins = append(ins, appscan.Instance{
			URL:      fmt.Sprintf("https://app.example.com/p%d?token=SECRET%d", i, i),
			Evidence: &appscan.Evidence{Method: "GET", Link: fmt.Sprintf("https://app.example.com/p%d", i)},
		})
	}
	tk := appscan.AppTicket{App: "Portal", Findings: []appscan.TicketFinding{{ID: "150001", Title: "x",
		Severity: 4, Status: "ACTIVE", Instances: ins}}}
	full := appscanFullText(tk, time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	if n := strings.Count(full, "request: GET"); n != maxEvidencePerFinding {
		t.Errorf("%d evidence blocks, want %d", n, maxEvidencePerFinding)
	}
	if strings.Contains(full, "SECRET") {
		t.Error("a token in a URL reached the attachment")
	}
}
