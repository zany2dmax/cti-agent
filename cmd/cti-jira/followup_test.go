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
	st := jira.StateFrom(jira.Finding{CVE: cve, Hosts: hosts}, key, time.Now().Add(-48*time.Hour))
	st.LastReportedAt = time.Now().Add(-30 * 24 * time.Hour) // outside the weekly limit
	fj.state[key] = st
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

// ─── noise: what counts as new, and how often IT hears about it ────────────

// reportedAt stores the set IT was told about, and when.
func reportedAt(fj *fakeJira, key, cve string, at time.Time, hosts ...string) {
	st := jira.StateFrom(jira.Finding{CVE: cve, Hosts: hosts}, key, at)
	st.LastReportedAt = at
	fj.state[key] = st
}

func present(hosts ...string) vulnlookup.Result {
	return vulnlookup.Result{Status: vulnlookup.StatusPresent, HostCount: len(hosts), Hosts: hosts}
}

func TestAHostThatMissedAScanIsNotNewWhenItComesBack(t *testing.T) {
	// The noise the operator's dry run exposed. One scan misses host-c; the
	// next sees it again. It was never gone from IT's point of view, and
	// announcing it as "newly affected" on a ticket with hundreds of hosts
	// happens most mornings.
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-40", "CVE-2026-4040", "indeterminate"))
	reportedAt(fj, "SEC-40", "CVE-2026-4040", now.Add(-10*24*time.Hour), "host-a", "host-b", "host-c")
	sc := &scanner{answers: map[string]vulnlookup.Result{}}

	sc.answers["CVE-2026-4040"] = present("host-a", "host-b") // the scan that missed one
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	if fj.propPuts["SEC-40"] != 0 {
		t.Fatal("a run that told IT nothing overwrote the set IT was told about")
	}

	sc.answers["CVE-2026-4040"] = present("host-a", "host-b", "host-c") // it is back
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now.Add(24*time.Hour), true)
	if n := len(fj.comments["SEC-40"]); n != 0 {
		t.Errorf("a host back from one missed scan was announced as new: %q", fj.comments["SEC-40"])
	}
}

func TestNewHostsAreHeldForAWeekAndThenReportedTogether(t *testing.T) {
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-41", "CVE-2026-4141", "indeterminate"))
	reportedAt(fj, "SEC-41", "CVE-2026-4141", now.Add(-2*24*time.Hour), "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{}}

	sc.answers["CVE-2026-4141"] = present("host-a", "host-b")
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	sc.answers["CVE-2026-4141"] = present("host-a", "host-b", "host-c")
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now.Add(24*time.Hour), true)
	if n := len(fj.comments["SEC-41"]); n != 0 {
		t.Fatalf("a host-change comment went out %d time(s) inside the week", n)
	}

	// Seven days after the last report: due. One comment, naming both.
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now.Add(5*24*time.Hour), true)
	got := fj.comments["SEC-41"]
	if len(got) != 1 {
		t.Fatalf("comments after the week = %d, want 1", len(got))
	}
	for _, h := range []string{"host-b", "host-c"} {
		if !strings.Contains(got[0], h) {
			t.Errorf("the batched comment does not name %s:\n%s", h, got[0])
		}
	}
	// And the clock restarts from that comment.
	sc.answers["CVE-2026-4141"] = present("host-a", "host-b", "host-c", "host-d")
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now.Add(6*24*time.Hour), true)
	if len(fj.comments["SEC-41"]) != 1 {
		t.Error("a second host-change comment went out a day after the first")
	}
}

func TestResolvedIsNeverHeld(t *testing.T) {
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-42", "CVE-2026-4242", "indeterminate"))
	reportedAt(fj, "SEC-42", "CVE-2026-4242", now.Add(-24*time.Hour), "host-a")
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-4242": {Status: vulnlookup.StatusNotPresent}}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	if len(fj.comments["SEC-42"]) != 1 || !strings.Contains(fj.comments["SEC-42"][0], "No detections remain") {
		t.Errorf("the all-clear was held: %q", fj.comments["SEC-42"])
	}
}

func TestAComebackAfterTheAllClearIsNotHeld(t *testing.T) {
	// IT was told it was gone yesterday. It is back. Waiting a week to say so
	// would make the all-clear look more trustworthy than it was.
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-43", "CVE-2026-4343", "indeterminate"))
	reportedAt(fj, "SEC-43", "CVE-2026-4343", now.Add(-24*time.Hour)) // zero hosts
	sc := &scanner{answers: map[string]vulnlookup.Result{"CVE-2026-4343": present("host-a")}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	if len(fj.comments["SEC-43"]) != 1 {
		t.Errorf("a regression after the all-clear was held: %q", fj.comments["SEC-43"])
	}
}

func TestANewQIDIsNotHeld(t *testing.T) {
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-44", "CVE-2026-4444", "indeterminate"))
	reportedAt(fj, "SEC-44", "CVE-2026-4444", now.Add(-24*time.Hour), "host-a")
	res := present("host-a")
	res.ExternalIDs = []string{"100001"}
	sc := &scanner{answers: map[string]vulnlookup.Result{"CVE-2026-4444": res}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	if len(fj.comments["SEC-44"]) != 1 {
		t.Errorf("a new QID was held: %q", fj.comments["SEC-44"])
	}
}

func TestThePreviewSaysWhenAHeldCommentIsDue(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	prev := jira.StateFrom(jira.Finding{CVE: "CVE-2026-4545", Hosts: []string{"host-a"}}, "SEC-45", now)
	prev.LastReportedAt = now.Add(-2 * 24 * time.Hour)
	f := jira.Finding{CVE: "CVE-2026-4545", Hosts: []string{"host-a", "host-b"}}
	got := planUpdate(issueIn("indeterminate"), &prev, f, now).describe(f)
	if !strings.Contains(got, "held for the weekly comment, due 2026-10-11") {
		t.Errorf("preview = %q", got)
	}
}

func TestTheSetupTestTicketIsRecognisedAndNotLookedUp(t *testing.T) {
	_, c := newFakeJira(t, ticket("SEC-46", testCVE, "indeterminate"))
	sc := &scanner{}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, time.Now(), true)
	if sc.calls[testCVE] != 0 {
		t.Error("the setup test ticket was sent to the scanner")
	}
}

func TestATestTicketDoesNotCarryTheLabelTheFollowUpSelectsOn(t *testing.T) {
	for _, l := range testLabels(testFinding(time.Now())) {
		if l == "cti-agent" {
			t.Fatal("a new test ticket would be picked up by the follow-up as a real one")
		}
	}
}

func TestTheUpgradeMorningStartsTheClockInsteadOfCommenting(t *testing.T) {
	// State from before the weekly limit has no LastReportedAt, and its host
	// list is the last RUN's - so "1 new host" against it is mostly a host one
	// scan missed. The operator's dry run showed three of four real tickets
	// about to be commented on for exactly that. Hold the change and start the
	// clock; a host still there in a week goes out in the normal comment.
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-47", "CVE-2026-4747", "indeterminate"))
	legacy := jira.StateFrom(jira.Finding{CVE: "CVE-2026-4747",
		Hosts: []string{"host-a", "host-b"}}, "SEC-47", now.Add(-3*24*time.Hour))
	fj.state["SEC-47"] = legacy // no LastReportedAt
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-4747": present("host-a", "host-c")}} // one swapped

	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	if n := len(fj.comments["SEC-47"]); n != 0 {
		t.Fatalf("the upgrade morning commented: %q", fj.comments["SEC-47"])
	}
	st := fj.state["SEC-47"]
	if st.LastReportedAt.IsZero() {
		t.Fatal("the weekly clock was not started")
	}
	if st.HostCount != 2 || !strings.Contains(strings.Join(st.Hosts, ","), "host-b") {
		t.Errorf("starting the clock rewrote the stored host list: %+v", st.Hosts)
	}

	// A week on, host-c is still there: it goes out, once.
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now.Add(7*24*time.Hour), true)
	got := fj.comments["SEC-47"]
	if len(got) != 1 || !strings.Contains(got[0], "host-c") {
		t.Errorf("after the week, comments = %q", got)
	}
}

func TestTheUpgradeMorningStillSaysResolved(t *testing.T) {
	now := time.Now()
	fj, c := newFakeJira(t, ticket("SEC-48", "CVE-2026-4848", "indeterminate"))
	fj.state["SEC-48"] = jira.StateFrom(jira.Finding{CVE: "CVE-2026-4848",
		Hosts: []string{"host-a"}}, "SEC-48", now.Add(-3*24*time.Hour))
	sc := &scanner{answers: map[string]vulnlookup.Result{
		"CVE-2026-4848": {Status: vulnlookup.StatusNotPresent}}}
	followUp(context.Background(), c, testCfg, sc.look, map[string]bool{}, now, true)
	if len(fj.comments["SEC-48"]) != 1 {
		t.Error("the all-clear was held on pre-upgrade state")
	}
}
