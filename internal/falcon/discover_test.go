package falcon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLiteralRefusesEverythingFQLGivesMeaningTo(t *testing.T) {
	for _, ok := range []string{"Google Chrome", "7-Zip", "Microsoft Visual Studio", "Adobe Inc.", "AT&T Global", "Node.js (x64)", "Python 3.12 / pip"} {
		if _, err := Literal(ok); err != nil {
			t.Errorf("Literal(%q) refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"x", strings.Repeat("a", 81),
		"chrome'+vendor:'x", `chrome\'`, "chrome*", "a+b", "name:chrome",
		"!chrome", "~chrome", "[chrome]", "a<b", "a>b", "a=b", "a|b", "chr\x00ome",
		"chrome\nname:x", "Notepad++", "Café", `"chrome"`,
	} {
		if v, err := Literal(bad); err == nil {
			t.Errorf("Literal(%q) = %q, want refused", bad, v)
		}
	}
	if v, _ := Literal("  Google   Chrome "); v != "Google Chrome" {
		t.Errorf("spaces not folded: %q", v)
	}
}

func TestClauses(t *testing.T) {
	if got := clause("name", "chrome", false); got != "name:*'*chrome*'" {
		t.Errorf("contains = %q", got)
	}
	if got := clause("vendor", "Google LLC", true); got != "vendor:'Google LLC'" {
		t.Errorf("exact = %q", got)
	}
}

// appsFake serves pages of Discover records and records every filter asked.
type appsFake struct {
	mu      sync.Mutex
	filters []string
	pages   [][]app
	total   int
	// before answers the "was it here before the window?" lookups by name.
	before map[string]int
}

func (a *appsFake) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := q.Get("filter")
	a.mu.Lock()
	a.filters = append(a.filters, f)
	a.mu.Unlock()
	if strings.Contains(f, "first_seen_timestamp:<=") {
		n := 0
		for name, c := range a.before {
			if strings.Contains(f, "name:'"+name+"'") {
				n = c
			}
		}
		_, _ = fmt.Fprintf(w, `{"meta":{"pagination":{"total":%d}},"resources":[]}`, n)
		return
	}
	i := 0
	if after := q.Get("after"); after != "" {
		_, _ = fmt.Sscanf(after, "p%d", &i)
	}
	next := ""
	if i+1 < len(a.pages) {
		next = fmt.Sprintf("p%d", i+1)
	}
	res, _ := json.Marshal(a.pages[i])
	_, _ = fmt.Fprintf(w, `{"meta":{"pagination":{"total":%d,"after":%q}},"resources":%s}`, a.total, next, res)
}

func rec(vendor, name, version, host, platform string) app {
	var a app
	a.Vendor, a.Name, a.Version = vendor, name, version
	a.Host.ID, a.Host.Platform = host, platform
	return a
}

func TestFindAppsPagesGroupsAndCountsHostsOnce(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 5, pages: [][]app{
		{rec("Google LLC", "Google Chrome", "131", "h1", "Windows"), rec("Google LLC", "Google Chrome", "131", "h1", "Windows")},
		{rec("Google LLC", "Google Chrome", "130", "h2", "Mac"), rec("google llc", "google chrome", "131", "h3", "Windows")},
		{rec("Other", "Chrome Remote Desktop", "", "h1", "Windows")},
	}}
	f.routes[appsRoute] = af.handler
	res, err := c.FindApps(context.Background(), "chrome", FindOpts{Vendor: "Google"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Filter != "name:*'*chrome*'+vendor:*'*Google*'" {
		t.Errorf("filter = %q", res.Filter)
	}
	if res.Read != 5 || res.Truncated || len(res.Apps) != 2 {
		t.Fatalf("read %d truncated %v apps %+v", res.Read, res.Truncated, res.Apps)
	}
	chrome := res.Apps[0]
	if chrome.Hosts != 3 || chrome.Versions["131"] != 2 || chrome.Versions["130"] != 1 || chrome.Platforms["Mac"] != 1 {
		t.Errorf("chrome = %+v", chrome)
	}
	if res.Apps[1].Versions["unknown"] != 1 {
		t.Errorf("an empty version should read unknown: %+v", res.Apps[1])
	}
	if len(af.filters) != 3 {
		t.Errorf("%d pages fetched, want 3", len(af.filters))
	}
}

func TestFindAppsStopsAtTheCapAndSaysSo(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 900, pages: [][]app{
		{rec("V", "App", "1", "h1", "Windows"), rec("V", "App", "1", "h2", "Windows")},
		{rec("V", "App", "1", "h3", "Windows"), rec("V", "App", "1", "h4", "Windows")},
		{rec("V", "App", "1", "h5", "Windows")},
	}}
	f.routes[appsRoute] = af.handler
	res, err := c.FindApps(context.Background(), "App", FindOpts{MaxRows: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || res.Read != 3 || res.Total != 900 {
		t.Fatalf("res = %+v", res)
	}
}

func TestAHostileNameNeverReachesTheAPI(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{pages: [][]app{{}}}
	f.routes[appsRoute] = af.handler
	if _, err := c.FindApps(context.Background(), "x'+name:*'*", FindOpts{}); err == nil {
		t.Fatal("want refused")
	}
	if _, err := c.FindApps(context.Background(), "chrome", FindOpts{Vendor: "a'+b"}); err == nil {
		t.Fatal("hostile vendor: want refused")
	}
	if len(af.filters) != 0 {
		t.Fatalf("the API was asked: %v", af.filters)
	}
}

func TestNewAppsSeparatesNewFromUpdatesAndUnusableNames(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 4, pages: [][]app{{
		rec("Acme", "Remote Helper", "2.0", "h1", "Windows"),
		rec("Acme", "Remote Helper", "2.0", "h2", "Windows"),
		rec("Google LLC", "Google Chrome", "132", "h1", "Windows"),
		rec("Odd", "Notepad++", "8", "h3", "Windows"),
	}}, before: map[string]int{"Google Chrome": 2000}}
	f.routes[appsRoute] = af.handler
	since := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	rep, err := c.NewApps(context.Background(), since, NewAppsOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.New) != 1 || rep.New[0].Name != "Remote Helper" || rep.New[0].Hosts != 2 {
		t.Errorf("new = %+v", rep.New)
	}
	if rep.SeenBefore != 1 {
		t.Errorf("seen before = %d, want 1", rep.SeenBefore)
	}
	if len(rep.NotChecked) != 1 || rep.NotChecked[0].Name != "Notepad++" {
		t.Errorf("not checked = %+v", rep.NotChecked)
	}
	if af.filters[0] != "first_seen_timestamp:>'2026-11-11T00:00:00Z'" {
		t.Errorf("window filter = %q", af.filters[0])
	}
	for _, f := range af.filters[1:] {
		if !strings.HasSuffix(f, "+first_seen_timestamp:<='2026-11-11T00:00:00Z'") || strings.Contains(f, "*") {
			t.Errorf("lookup filter = %q", f)
		}
	}
}

func TestNewAppsRespectsTheCheckCap(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 3, pages: [][]app{{
		rec("Aa", "One", "1", "h1", "Windows"), rec("Bb", "Two", "1", "h2", "Windows"), rec("Cc", "Three", "1", "h3", "Windows"),
	}}}
	f.routes[appsRoute] = af.handler
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{MaxChecks: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.New) != 1 || len(rep.NotChecked) != 2 {
		t.Fatalf("new %d, not checked %d; want 1 and 2", len(rep.New), len(rep.NotChecked))
	}
}

func TestAHostWithTwoVersionsCountsTowardBoth(t *testing.T) {
	got := summarise([]app{
		rec("Oracle", "Java", "8", "h1", "Windows"),
		rec("Oracle", "Java", "17", "h1", "Windows"),
		rec("Oracle", "Java", "17", "h2", "Windows"),
		rec("Oracle", "Java", "17", "", "Windows"),
		rec("Oracle", "Java", "17", "", "Windows"),
	})
	j := got[0]
	if j.Hosts != 2 || j.Versions["8"] != 1 || j.Versions["17"] != 2 || j.Platforms["Windows"] != 2 || j.NoHost != 2 {
		t.Fatalf("java = %+v", j)
	}
}

func TestTruncatedOnlyWhenRecordsWereLeft(t *testing.T) {
	f, c := newFake(t)
	// Exactly the cap, but the API still hands back a cursor on the last page.
	af := &appsFake{total: 2, pages: [][]app{
		{rec("Vv", "App", "1", "h1", "Windows"), rec("Vv", "App", "1", "h2", "Windows")},
		{},
	}}
	f.routes[appsRoute] = af.handler
	res, err := c.FindApps(context.Background(), "App", FindOpts{MaxRows: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Fatalf("every record was read but it says truncated: %+v", res)
	}
}

func TestAnAppWithNoVendorIsNotCheckedAgainstEveryVendor(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 1, pages: [][]app{{rec("", "AnyDesk", "9", "h1", "Windows")}},
		before: map[string]int{"AnyDesk": 50}}
	f.routes[appsRoute] = af.handler
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SeenBefore != 0 || len(rep.NotChecked) != 1 {
		t.Fatalf("a vendorless name was matched against other vendors: %+v", rep)
	}
	if len(af.filters) != 1 {
		t.Fatalf("a lookup was made: %v", af.filters)
	}
}

func TestStoredSpellingIsUsedForTheExactLookup(t *testing.T) {
	if v, err := exactLiteral("Some  App"); err != nil || v != "Some  App" {
		t.Fatalf("exactLiteral folded or refused: %q %v", v, err)
	}
	if _, err := exactLiteral(" App"); err == nil {
		t.Fatal("leading space accepted")
	}
	if _, err := Literal("a,b"); err == nil {
		t.Fatal("comma (FQL OR) accepted")
	}
}
