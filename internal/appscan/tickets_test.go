package appscan

import (
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/ticketref"
)

func scanWith(app, id string, fs ...Finding) ScanResult {
	return ScanResult{Provider: "qualys-was", App: app, AppID: id, Complete: true,
		Finished: time.Date(2026, 10, 19, 2, 0, 0, 0, time.UTC), Open: fs, OpenFetched: true}
}

func TestOnlyActiveConfirmedSeriousAndAboveAreTicketed(t *testing.T) {
	fix := &Remedy{Solution: "Encode output."}
	s := scanWith("Portal", "101",
		Finding{ID: "150001", Title: "XSS", Severity: 5, Status: "NEW", URL: "https://app.example.com/a", Param: "q", Remedy: fix},
		Finding{ID: "150001", Title: "XSS", Severity: 5, Status: "ACTIVE", URL: "https://app.example.com/b", Param: "q"},
		Finding{ID: "150001", Title: "XSS", Severity: 5, Status: "ACTIVE", URL: "https://app.example.com/a", Param: "q"}, // duplicate place
		Finding{ID: "150002", Title: "SQLi", Severity: 4, Status: "REOPENED", URL: "https://app.example.com/c"},
		Finding{ID: "150003", Title: "Potential", Severity: 5, Status: "NEW", Potential: true},
		Finding{ID: "150004", Title: "Ignored", Severity: 5, Status: "ACTIVE", Ignored: true},
		Finding{ID: "150005", Title: "Fixed", Severity: 5, Status: "FIXED"},
		Finding{ID: "150006", Title: "Cookie flag", Severity: 2, Status: "ACTIVE"},
		Finding{ID: "150007", Title: "Banner", Severity: 1, Status: "NEW"},
	)
	tf := BuildTickets([]ScanResult{s}, Owners{}, time.Now())
	if len(tf.Tickets) != 1 {
		t.Fatalf("tickets %d", len(tf.Tickets))
	}
	tk := tf.Tickets[0]
	if tk.Skip != "" || len(tk.Findings) != 2 || tk.Lower != 2 {
		t.Fatalf("skip %q findings %d lower %d", tk.Skip, len(tk.Findings), tk.Lower)
	}
	x := tk.Findings[0]
	if x.ID != "150001" || len(x.Instances) != 2 || x.Status != "NEW" || x.Remedy == nil {
		t.Errorf("grouped XSS: %+v", x)
	}
	if tk.Findings[1].ID != "150002" {
		t.Errorf("not ordered by severity: %+v", tk.Findings)
	}
	if tk.OwnerListed {
		t.Error("an owner appeared from nowhere")
	}
}

func TestAFaultyScanOrMissingDetailIsNeverToldItIsClean(t *testing.T) {
	incomplete := scanWith("A", "1")
	incomplete.Complete = false
	authFail := scanWith("B", "2")
	authFail.Auth = Auth{Record: "login", Status: "Failed"}
	noDetail := scanWith("C", "3")
	noDetail.OpenFetched = false
	noID := scanWith("D", "")
	discovery := scanWith("E", "5")
	discovery.ScanType = "DISCOVERY"
	tf := BuildTickets([]ScanResult{incomplete, authFail, noDetail, noID, discovery}, Owners{}, time.Now())
	if len(tf.Tickets) != 5 {
		t.Fatalf("tickets %d", len(tf.Tickets))
	}
	for _, tk := range tf.Tickets {
		if tk.Skip == "" {
			t.Errorf("%s: an untrustworthy week would tell its ticket nothing is left", tk.App)
		}
		if len(tk.Findings) != 0 {
			t.Errorf("%s: findings listed from a skipped scan", tk.App)
		}
	}
}

func TestTheOwnerAndAStableHashAndLabel(t *testing.T) {
	o, _, _ := ParseOwners(strings.NewReader("id:101 | lead@example.com | Web\n"))
	s := scanWith("Portal", "101", Finding{ID: "1", Severity: 4, Status: "ACTIVE", URL: "u"})
	a := BuildTickets([]ScanResult{s}, o, time.Now()).Tickets[0]
	b := BuildTickets([]ScanResult{s}, o, time.Now().Add(time.Hour)).Tickets[0]
	if !a.OwnerListed || a.Owner != "lead@example.com" || a.Component != "Web" {
		t.Errorf("owner %+v", a)
	}
	if a.Hash != b.Hash || a.Hash == "" {
		t.Errorf("hash not stable: %q %q", a.Hash, b.Hash)
	}
	if got := AppLabel(a.Key); got != "cti-appscan-101" {
		t.Errorf("label %q", got)
	}
	if a, b := AppLabel("id:ABC"), AppLabel("id:XYZ"); a == b || a == "cti-appscan-" {
		t.Errorf("odd ids must not share a label: %q %q", a, b)
	}
	l1, l2 := AppLabel("name:my app"), AppLabel("name:my-app")
	if l1 == l2 || strings.ContainsAny(l1, " _") {
		t.Errorf("name labels collide or are not label-safe: %q %q", l1, l2)
	}
}

func TestTheEmailShowsAFixAndEachTicket(t *testing.T) {
	fix := &Remedy{Solution: "Encode all output for its context. Then retest."}
	if got := FixSummary(fix); got != "Encode all output for its context." {
		t.Errorf("fix summary %q", got)
	}
	tf := TicketsFile{Unowned: []string{"Orphan App"}, Tickets: []AppTicket{
		{Key: "id:1", App: "Portal", OwnerListed: true, Findings: make([]TicketFinding, 2)},
		{Key: "id:2", App: "Shop", Skip: "the scan did not complete"},
		{Key: "id:3", App: "Quiet"},
	}}
	body := "a\n" + TicketsSlot + "\nb"
	refs := map[string]ticketref.Ref{
		"id:1": {Action: "created", Key: "SEC-9", URL: "https://jira.example.com/browse/SEC-9", Assignee: "lead@example.com"},
		"id:2": {Action: "skipped", Note: "the scan did not complete"},
		"id:3": {Action: "none"},
	}
	text := StampTickets(body, false, tf, refs)
	for _, want := range []string{"Portal: filed SEC-9 with 2 finding(s) to fix. Assigned to lead@example.com.",
		"https://jira.example.com/browse/SEC-9", "Shop: ticket not updated - the scan did not complete.",
		"No owner in app-owners.txt (1): Orphan App"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Quiet") || strings.Contains(text, TicketsSlot) {
		t.Errorf("nothing-to-say app listed, or slot left:\n%s", text)
	}
	if got := StampTickets(body, true, tf, nil); !strings.Contains(got, "unavailable") {
		t.Errorf("no refs at all must say unavailable: %s", got)
	}
}

func TestASlotInsideObservedDataIsNotAStampSite(t *testing.T) {
	s := scanWith("Portal "+TicketsSlot, "1")
	b := RenderWithTicketSlot([]ScanResult{s}, time.Now())
	for name, body := range map[string]string{"text": b.Text, "html": b.HTML} {
		if n := strings.Count(body, TicketsSlot); n != 1 {
			t.Errorf("%s: %d slots, want 1", name, n)
		}
	}
	if strings.Contains(Render([]ScanResult{s}, time.Now()).Text, TicketsSlot) {
		t.Error("a slot in a report nobody will stamp")
	}
}

func TestTheEmailListsLiveWebsitesNobodyScans(t *testing.T) {
	tf := TicketsFile{SitesAsOf: time.Date(2026, 10, 19, 4, 0, 0, 0, time.UTC),
		NotScanned: []NotScanned{{Domain: "shop.example.net", Owner: "web@example.com"}, {Domain: "brochure.example.com"}}}
	for _, isHTML := range []bool{false, true} {
		got := StampTickets("x"+TicketsSlot, isHTML, tf, map[string]ticketref.Ref{})
		for _, want := range []string{"NOT SCANNED (2)", "shop.example.net", "owner web@example.com",
			"add a site: line", "2026-10-19"} {
			if !strings.Contains(got, want) {
				t.Errorf("html=%v missing %q:\n%s", isHTML, want, got)
			}
		}
	}
}

func TestTheEmailSaysWhatIsCoveredOnlyViaStaging(t *testing.T) {
	tf := TicketsFile{ViaStandIn: []ViaStandIn{{Domain: "example.com", AppID: "500", AppName: "Site (staging)",
		AppHost: "site-stg.wpenginepowered.com"}},
		Tickets: []AppTicket{{Key: "id:500", App: "Site (staging)", Covers: []string{"example.com"}}}}
	refs := map[string]ticketref.Ref{"id:500": {Action: "unchanged", Key: "SEC-1"}}
	got := StampTickets(TicketsSlot, false, tf, refs)
	for _, w := range []string{"COVERED VIA STAGING (1)", "example.com - via site-stg.wpenginepowered.com",
		"production not scanned directly", "Site (staging) (stands in for example.com): SEC-1"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q:\n%s", w, got)
		}
	}
}

func TestBuildTicketsCarriesTheWatchers(t *testing.T) {
	o, _, _ := ParseOwners(strings.NewReader("id:101 | lead@example.com | watchers=qa@example.com,pm@example.com\n"))
	s := scanWith("Portal", "101", Finding{ID: "1", Severity: 4, Status: "ACTIVE", URL: "u"})
	a := BuildTickets([]ScanResult{s}, o, time.Now()).Tickets[0]
	if len(a.Watchers) != 2 || a.Watchers[0] != "qa@example.com" || a.Watchers[1] != "pm@example.com" {
		t.Errorf("watchers %v", a.Watchers)
	}
}
