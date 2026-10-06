package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
)

// fakeJira serves the four endpoints the follow-up touches and records what
// was written. Synthetic keys and CVEs throughout.
type fakeJira struct {
	mu       sync.Mutex
	issues   []map[string]any
	state    map[string]jira.ExposureState // by issue key
	comments map[string][]string
	propPuts map[string]int
}

func newFakeJira(t *testing.T, issues ...map[string]any) (*fakeJira, *jira.Client) {
	t.Helper()
	fj := &fakeJira{issues: issues, state: map[string]jira.ExposureState{},
		comments: map[string][]string{}, propPuts: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fj.mu.Lock()
		defer fj.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		p := r.URL.Path
		switch {
		case r.Method == http.MethodPost && p == "/rest/api/3/search/jql":
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": fj.issues, "isLast": true})
		case strings.Contains(p, "/properties/"):
			key := strings.Split(strings.TrimPrefix(p, "/rest/api/2/issue/"), "/")[0]
			if r.Method == http.MethodGet {
				st, ok := fj.state[key]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"key": jira.PropertyKey, "value": st})
				return
			}
			var st jira.ExposureState
			_ = json.Unmarshal(body, &st)
			fj.state[key] = st
			fj.propPuts[key]++
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

func ticket(key, cve, category string) map[string]any {
	return map[string]any{
		"key": key,
		"fields": map[string]any{
			"summary": "synthetic",
			"status": map[string]any{"name": "In Progress",
				"statusCategory": map[string]any{"key": category}},
			"labels": []string{"cti-" + strings.ToLower(cve), "cti-agent"},
		},
	}
}

// scanner answers per CVE, counting the calls it receives.
type scanner struct {
	answers map[string]vulnlookup.Result
	errs    map[string]error
	calls   map[string]int
}

func (s *scanner) look(_ context.Context, cve string) (vulnlookup.Result, error) {
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[cve]++
	return s.answers[cve], s.errs[cve]
}

var testCfg = config.Config{JiraProjectKey: "SEC"}

func previously(fj *fakeJira, key, cve string, hosts ...string) {
	fj.state[key] = jira.StateFrom(jira.Finding{CVE: cve, Hosts: hosts}, key, time.Now().Add(-48*time.Hour))
}

func TestAFixedVulnerabilityFinallyGetsItsResolvedComment(t *testing.T) {
	// The comment existed and could never be sent: the morning path keeps
	// PRESENT findings only, and a fixed CVE is not present.
	fj, c := newFakeJira(t, ticket("SEC-1", "CVE-2026-1111", "indeterminate"))
	previously(fj, "SEC-1", "CVE-2026-1111", "host-a", "host-b", "host-c")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-1111": {CVE: "CVE-2026-1111", Status: vulnlookup.StatusNotPresent},
	}}

	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)

	got := fj.comments["SEC-1"]
	if len(got) != 1 || !strings.Contains(got[0], "No detections remain") {
		t.Fatalf("comments = %q, want one 'No detections remain'", got)
	}
	if !strings.Contains(got[0], "(was 3)") {
		t.Errorf("the comment does not say how many hosts it was: %q", got[0])
	}
}

func TestAFailedLookupNeverSaysResolved(t *testing.T) {
	// THE ONE THAT MATTERS. A Qualys outage is reported as UNKNOWN with an
	// error and zero hosts. Read as "zero detections", it would tell IT a
	// live exposure was fixed.
	fj, c := newFakeJira(t, ticket("SEC-2", "CVE-2026-2222", "indeterminate"))
	previously(fj, "SEC-2", "CVE-2026-2222", "host-a", "host-b")
	sc := &scanner{
		answers: map[string]vulnlookup.Result{"CVE-2026-2222": {Status: vulnlookup.StatusUnknown}},
		errs:    map[string]error{"CVE-2026-2222": errors.New("connection reset")},
	}

	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)

	if n := len(fj.comments["SEC-2"]); n != 0 {
		t.Errorf("a failed lookup produced %d comment(s): %q", n, fj.comments["SEC-2"])
	}
	if fj.propPuts["SEC-2"] != 0 {
		t.Error("a failed lookup overwrote the stored exposure - the next real answer would then compare against zero")
	}
}

func TestAnUnknownAnswerWithoutAnErrorIsAlsoNotAFix(t *testing.T) {
	// No QID mapping yet: no error, status UNKNOWN, zero hosts.
	fj, c := newFakeJira(t, ticket("SEC-3", "CVE-2026-3333", "indeterminate"))
	previously(fj, "SEC-3", "CVE-2026-3333", "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-3333": {Status: vulnlookup.StatusUnknown, Reason: "no QID mapping"},
	}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)
	if len(fj.comments["SEC-3"]) != 0 || fj.propPuts["SEC-3"] != 0 {
		t.Error("an UNKNOWN answer was compared with the ticket")
	}
}

func TestNotPresentWithAnErrorIsRefused(t *testing.T) {
	if ok, _ := followUpVerdict(vulnlookup.Result{Status: vulnlookup.StatusNotPresent},
		errors.New("partial page")); ok {
		t.Error("an answer that came with an error was trusted")
	}
}

func TestSpreadOnAQuietTicketIsReported(t *testing.T) {
	// The other half of the gap: a ticket whose CVE is no longer in the mail
	// used to be invisible however far it spread.
	fj, c := newFakeJira(t, ticket("SEC-4", "CVE-2026-4444", "new"))
	previously(fj, "SEC-4", "CVE-2026-4444", "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{"CVE-2026-4444": {
		Status: vulnlookup.StatusPresent, HostCount: 3,
		Hosts: []string{"host-a", "host-b", "host-c"}, ExternalIDs: []string{"100001"}}}}

	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)

	if len(fj.comments["SEC-4"]) != 1 {
		t.Fatalf("spread to two new hosts was not commented: %q", fj.comments["SEC-4"])
	}
}

func TestNoChangeMeansNoComment(t *testing.T) {
	fj, c := newFakeJira(t, ticket("SEC-5", "CVE-2026-5555", "indeterminate"))
	previously(fj, "SEC-5", "CVE-2026-5555", "host-a", "host-b")
	sc := &scanner{answers: map[string]vulnlookup.Result{"CVE-2026-5555": {
		Status: vulnlookup.StatusPresent, HostCount: 2, Hosts: []string{"host-a", "host-b"}}}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)
	if len(fj.comments["SEC-5"]) != 0 {
		t.Errorf("an unchanged ticket was commented on - daily, that is a storm: %q",
			fj.comments["SEC-5"])
	}
}

func TestATicketHandledThisMorningIsNotComparedTwice(t *testing.T) {
	_, c := newFakeJira(t, ticket("SEC-6", "CVE-2026-6666", "indeterminate"))
	sc := &scanner{}
	followUp(context.Background(), c, testCfg, sc.look,
		map[string]bool{"CVE-2026-6666": true}, time.Now(), true)
	if sc.calls["CVE-2026-6666"] != 0 {
		t.Error("a CVE the morning path already handled was looked up again")
	}
}

func TestATicketWithNoCVELabelIsLeftAlone(t *testing.T) {
	issue := ticket("SEC-7", "CVE-2026-7777", "indeterminate")
	issue["fields"].(map[string]any)["labels"] = []string{"cti-agent"}
	fj, c := newFakeJira(t, issue)
	sc := &scanner{}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)
	if len(sc.calls) != 0 || len(fj.comments) != 0 {
		t.Error("a ticket with no CVE label was acted on")
	}
}

func TestADryRunWritesNothing(t *testing.T) {
	fj, c := newFakeJira(t, ticket("SEC-8", "CVE-2026-8888", "indeterminate"))
	previously(fj, "SEC-8", "CVE-2026-8888", "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-8888": {Status: vulnlookup.StatusNotPresent}}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), false)
	if len(fj.comments["SEC-8"]) != 0 || fj.propPuts["SEC-8"] != 0 {
		t.Error("a dry run wrote to Jira")
	}
}

func TestTheSearchSelectsTheFleetsOwnTickets(t *testing.T) {
	q := followUpJQL("SEC")
	for _, want := range []string{`project = "SEC"`, `labels = "cti-agent"`,
		`statusCategory != Done`, `updated >= -30d`} {
		if !strings.Contains(q, want) {
			t.Errorf("JQL lacks %s: %s", want, q)
		}
	}
}

func TestTheCVEComesFromTheIdempotencyLabel(t *testing.T) {
	for labels, want := range map[string]string{
		"cti-agent,cti-cve-2026-1234": "CVE-2026-1234",
		"CTI-CVE-2026-9,cti-agent":    "CVE-2026-9",
		"cti-agent,urgent":            "",
	} {
		if got := cveFromLabels(strings.Split(labels, ",")); got != want {
			t.Errorf("cveFromLabels(%s) = %q, want %q", labels, got, want)
		}
	}
	// And it is the inverse of the label the fleet writes.
	if got := cveFromLabels([]string{jira.IdempotencyLabel("CVE-2026-4242")}); got != "CVE-2026-4242" {
		t.Errorf("round trip through IdempotencyLabel = %q", got)
	}
}

// ─── through the entry point the operator runs ─────────────────────────────

// withScanner swaps the real Qualys lookup for a fake for one test.
func withScanner(t *testing.T, sc *scanner) {
	t.Helper()
	saved := scannerFor
	scannerFor = func(context.Context, config.Config) (hostFiller, error) { return sc.look, nil }
	t.Cleanup(func() { scannerFor = saved })
}

func TestTheFollowUpFlagReachesTheFollowUp(t *testing.T) {
	// THE REGRESSION THIS FILE MISSED. The commit that added --follow-up never
	// called followUp() from doFromEnriched. The flag parsed, Go accepted the
	// unused parameter, and every test above passed because they call
	// followUp() directly. The operator's dry run against four open tickets
	// printed no follow-up line at all, and that was the first sign.
	fj, c := newFakeJira(t, ticket("SEC-20", "CVE-2026-2020", "indeterminate"))
	previously(fj, "SEC-20", "CVE-2026-2020", "host-a", "host-b")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-2020": {Status: vulnlookup.StatusNotPresent}}}
	withScanner(t, sc)

	// Today's findings exist but none qualifies - the shape of the real run.
	path := writeEnriched(t, `{"findings":[{"cve":"CVE-2026-0001","status":"NOT_PRESENT","priority":"Sev3"}]}`)
	doFromEnriched(context.Background(), c, testCfg, path, true, false, true)

	if sc.calls["CVE-2026-2020"] != 1 {
		t.Fatalf("--follow-up did not re-check the open ticket (lookups: %v)", sc.calls)
	}
	if len(fj.comments["SEC-20"]) != 1 {
		t.Errorf("the fixed CVE got no resolved comment: %q", fj.comments["SEC-20"])
	}
}

func TestWithoutTheFlagNoTicketIsReChecked(t *testing.T) {
	fj, c := newFakeJira(t, ticket("SEC-21", "CVE-2026-2121", "indeterminate"))
	previously(fj, "SEC-21", "CVE-2026-2121", "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-2121": {Status: vulnlookup.StatusNotPresent}}}
	withScanner(t, sc)
	path := writeEnriched(t, `{"findings":[]}`)
	doFromEnriched(context.Background(), c, testCfg, path, true, false, false)
	if len(sc.calls) != 0 || len(fj.comments) != 0 {
		t.Error("tickets were re-checked without --follow-up")
	}
}

func TestTheFollowUpRunsWithNoFindingsFileAtAll(t *testing.T) {
	// It used to return on a missing enriched file before reaching the
	// follow-up, saying only "no tickets this run".
	fj, c := newFakeJira(t, ticket("SEC-22", "CVE-2026-2222", "indeterminate"))
	previously(fj, "SEC-22", "CVE-2026-2222", "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-2222": {Status: vulnlookup.StatusNotPresent}}}
	withScanner(t, sc)

	for _, path := range []string{"", t.TempDir() + "/does-not-exist.json"} {
		sc.calls = nil
		doFromEnriched(context.Background(), c, testCfg, path, false, false, true)
		if sc.calls["CVE-2026-2222"] != 1 {
			t.Errorf("path %q: the follow-up did not run", path)
		}
	}
	if len(fj.comments) != 0 {
		t.Error("a dry run commented")
	}
}

func TestAScannerThatWillNotLoadStopsTheFollowUpAndSaysSo(t *testing.T) {
	fj, c := newFakeJira(t, ticket("SEC-23", "CVE-2026-2323", "indeterminate"))
	saved := scannerFor
	scannerFor = func(context.Context, config.Config) (hostFiller, error) {
		return nil, errors.New("kb cache: permission denied")
	}
	t.Cleanup(func() { scannerFor = saved })
	doFromEnriched(context.Background(), c, testCfg, "", true, false, true)
	if len(fj.comments) != 0 {
		t.Error("tickets were touched with no scanner to compare against")
	}
}

func writeEnriched(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/enriched-2026-10-06.json"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
