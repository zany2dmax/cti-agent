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
	// before answers the "was it here before the window?" lookups by exact
	// name; beforePattern the any-version ones, keyed by pattern.
	before        map[string]int
	beforePattern map[string][]string // pattern -> earlier names it returns
}

func (a *appsFake) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := q.Get("filter")
	if !strings.Contains(f, "first_seen_timestamp:<=") && q.Get("facet") != "host_info" {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"errors":[{"code":400,"message":"test fake: paged reads must ask for facet=host_info"}]}`))
		return
	}
	a.mu.Lock()
	a.filters = append(a.filters, f)
	a.mu.Unlock()
	if strings.Contains(f, "first_seen_timestamp:<=") {
		n := 0
		for name, c := range a.before {
			if strings.HasPrefix(f, "name:'"+name+"'+") {
				n = c
			}
		}
		for pat, names := range a.beforePattern {
			if strings.HasPrefix(f, "name:*'"+pat+"'+") {
				var rs []app
				for _, nm := range names {
					rs = append(rs, rec("x", nm, "", "h9", "Windows"))
				}
				b, _ := json.Marshal(rs)
				_, _ = fmt.Fprintf(w, `{"meta":{"pagination":{"total":%d}},"resources":%s}`, len(rs), b)
				return
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
		rec("Odd", "Bad'Name", "8", "h3", "Windows"),
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
	if len(rep.NotChecked) != 1 || rep.NotChecked[0].Name != "Bad'Name" || rep.Reasons[ReasonRefused] != 1 {
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
	if len(rep.New) != 1 || len(rep.NotChecked) != 2 || rep.Reasons[ReasonOverCap] != 2 {
		t.Fatalf("new %d, not checked %d (%v); want 1 and 2 over the cap", len(rep.New), len(rep.NotChecked), rep.Reasons)
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
	if rep.SeenBefore != 0 || len(rep.NotChecked) != 1 || rep.Reasons[ReasonNoVendor] != 1 {
		t.Fatalf("a vendorless name was matched against other vendors: %+v", rep)
	}
	if len(af.filters) != 1 {
		t.Fatalf("a lookup was made: %v", af.filters)
	}
}

func TestNamesDiscoverReturnedAreCheckedLooselyButSafely(t *testing.T) {
	for _, ok := range []string{"Some  App", "Keeper® Password Manager & Digital Vault", "iCloud+.app",
		"Adobe Acrobat: PDF edit, convert, sign tools", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
		"Microsoft 365 企业应用版 - zh-cn", "엔터프라이즈용 Microsoft 365 앱 - ko-kr"} {
		if v, err := apiLiteral(ok); err != nil || v != ok {
			t.Errorf("apiLiteral(%q) = %q, %v", ok, v, err)
		}
	}
	for _, bad := range []string{"", " App", "App ", "it's", `a\b`, "a*b", "a\nb", "a\x1bb", "\xff\xfe", strings.Repeat("a", 301)} {
		if _, err := apiLiteral(bad); err == nil {
			t.Errorf("apiLiteral(%q) accepted", bad)
		}
	}
	if _, err := Literal("a,b"); err == nil {
		t.Fatal("comma (FQL OR) accepted from an advisory")
	}
}

func TestVersionPatterns(t *testing.T) {
	cases := map[string]string{
		"Microsoft .NET 8.0.34 - Windows Server Hosting":               "Microsoft .NET * - Windows Server Hosting",
		"Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247": "Microsoft Visual C++ v14 Redistributable (x64) - *",
		"Dash ddxPrinter 8.20.6.26.1":                                  "Dash ddxPrinter *",
		"PowerShell 7.6.10.0-x64":                                      "PowerShell *",
		"Bluebeam Vu x64 2015":                                         "", // a year, not a version
		"Google Chrome":                                                "",
		"1.2 3.4":                                                      "", // nothing left
	}
	for in, want := range cases {
		if got := versionPattern(in); got != want {
			t.Errorf("versionPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnUpdateWithTheVersionInItsNameIsSeenBefore(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 2, pages: [][]app{{
		rec("Microsoft Corporation", "Microsoft .NET 8.0.34 - Windows Server Hosting", "8.0.34", "h1", "Windows"),
		rec("Acme", "Remote Helper 2.0.1", "2.0.1", "h2", "Windows"),
		rec("Zoom Video", "Zoom 6.1.0", "6.1.0", "h3", "Windows"),
	}}, beforePattern: map[string][]string{
		"Microsoft .NET * - Windows Server Hosting": {"Microsoft .NET 8.0.33 - Windows Server Hosting"},
		// Only a different product matches the wildcard: not seen before.
		"Zoom *": {"Zoom Rooms", "Zoom Outlook Plugin"},
	}}
	f.routes[appsRoute] = af.handler
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SeenBefore != 1 || rep.SeenAsOtherVersion != 1 {
		t.Errorf("seen %d, other version %d; want 1 and 1", rep.SeenBefore, rep.SeenAsOtherVersion)
	}
	if len(rep.New) != 2 {
		t.Errorf("new = %+v, want Remote Helper and Zoom", rep.New)
	}
}

func TestALookupFailureFailsTheRunInsteadOfCallingItNew(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 1, pages: [][]app{{rec("Acme", "Remote Helper", "1", "h1", "Windows")}}}
	f.routes[appsRoute] = func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("filter"), "first_seen_timestamp:<=") {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"errors":[{"code":500,"message":"boom"}]}`))
			return
		}
		af.handler(w, r)
	}
	if rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{}); err == nil {
		t.Fatalf("want an error, got %+v", rep)
	}
}

func TestFieldNamesNeverCarryValues(t *testing.T) {
	f, c := newFake(t)
	f.routes[appsRoute] = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{},"resources":[{"name":"SecretApp","host":{"hostname":"HOST-42","platform_name":"Windows","groups":["g1"]}}]}`))
	}
	got, err := c.FieldNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(got, "\n")
	for _, v := range []string{"SecretApp", "HOST-42", "Windows", "g1"} {
		if strings.Contains(all, v) {
			t.Fatalf("a value leaked: %q", all)
		}
	}
	if !strings.Contains(all, "host.platform_name (string)") || !strings.Contains(all, "host.groups (array of 1)") {
		t.Fatalf("fields = %q", all)
	}
}

func TestOneRejectedLookupMarksOneAppNotTheRun(t *testing.T) {
	f, c := newFake(t)
	af := &appsFake{total: 2, pages: [][]app{{
		rec("Acme", "Odd+Name", "1", "h1", "Windows"),
		rec("Acme", "Remote Helper", "1", "h2", "Windows"),
	}}}
	f.routes[appsRoute] = func(w http.ResponseWriter, r *http.Request) {
		if fl := r.URL.Query().Get("filter"); strings.Contains(fl, "Odd+Name") {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"meta":{"trace_id":"t"},"errors":[{"code":400,"message":"invalid filter"}]}`))
			return
		}
		af.handler(w, r)
	}
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{})
	if err != nil {
		t.Fatalf("one bad name failed the run: %v", err)
	}
	if rep.Reasons[ReasonRejected] != 1 || len(rep.New) != 1 {
		t.Fatalf("rep = %+v", rep)
	}
}

func TestADifferentEditionIsNotAnotherVersion(t *testing.T) {
	// "-client" is not a known suffix, so "2.0-client" is not a version
	// token and the name gets no pattern at all.
	if p := versionPattern("Acme Agent 2.0-client"); p != "" {
		t.Fatalf("pattern = %q, want none", p)
	}
	re := patternRegexp(versionPattern("PowerShell 7.6.10.0-x64"))
	if !re.MatchString("PowerShell 7.4.1.0-x64") || re.MatchString("PowerShell Preview") {
		t.Fatal("x64 build suffix not handled")
	}
}

func TestFieldNamesDoNotOpenDataKeyedObjectsOrPrintBidi(t *testing.T) {
	f, c := newFake(t)
	keys := []string{}
	for i := 0; i < 50; i++ {
		keys = append(keys, fmt.Sprintf(`"HOST-%d":1`, i))
	}
	f.routes[appsRoute] = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"meta":{},"resources":[{"by_host":{%s},"na\u202eme":"x"}]}`, strings.Join(keys, ","))
	}
	got, err := c.FieldNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(got, "\n")
	if strings.Contains(all, "HOST-") || strings.Contains(all, "\u202e") || !strings.Contains(all, "not opened") {
		t.Fatalf("fields = %q", all)
	}
}

func TestATotalTheAPIDidNotSendIsUnknownNotTheReadCount(t *testing.T) {
	f, c := newFake(t)
	f.routes[appsRoute] = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{},"resources":[{"name":"App","vendor":"Vv","host":{"id":"h1"}}]}`))
	}
	res, err := c.FindApps(context.Background(), "App", FindOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != -1 || res.Read != 1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestAnExtensionIsLookedUpOnlyAmongExtensions(t *testing.T) {
	f, c := newFake(t)
	ext := rec("", "HubSpot Sales", "3.4", "h1", "Windows")
	ext.SoftwareType = "browser_extension"
	af := &appsFake{total: 1, pages: [][]app{{ext}}, before: map[string]int{"HubSpot Sales": 9}}
	f.routes[appsRoute] = af.handler
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SeenBefore != 1 || rep.ByType != 1 || len(rep.NotChecked) != 0 {
		t.Fatalf("rep = %+v", rep)
	}
	lookup := af.filters[len(af.filters)-1]
	if !strings.Contains(lookup, "+software_type:'browser_extension'+") || strings.Contains(lookup, "vendor:") {
		t.Fatalf("lookup = %q", lookup)
	}
}

func TestHostFactsAreCountedPerHost(t *testing.T) {
	a := rec("Kaseya", "RMM Agent.app", "4.4", "h1", "Mac")
	a.Host.HostType, a.Host.Exposure, a.Host.Criticality, a.IsSuspicious = "Workstation", "Not exposed", "Unassigned", true
	b := rec("Kaseya", "RMM Agent.app", "4.4", "h2", "Windows")
	b.Host.HostType = "Server"
	got := summarise([]app{a, a, b})[0]
	if got.Hosts != 2 || got.Suspicious != 1 || got.HostTypes["Workstation"] != 1 || got.HostTypes["Server"] != 1 ||
		got.Exposure["Not exposed"] != 1 || got.Exposure["unknown"] != 1 || got.Criticality["Unassigned"] != 1 {
		t.Fatalf("summary = %+v", got)
	}
}

func TestTheSameNameAsAnAppAndAnExtensionAreKeptApart(t *testing.T) {
	app1 := rec("", "Grammarly", "1", "h1", "Windows")
	app1.SoftwareType = "application"
	ext := rec("", "Grammarly", "1", "h2", "Windows")
	ext.SoftwareType = "browser_extension"
	if got := summarise([]app{app1, ext}); len(got) != 2 {
		t.Fatalf("merged: %+v", got)
	}
}

func TestAVendorlessDesktopAppIsNotLookedUpByNameAlone(t *testing.T) {
	f, c := newFake(t)
	a := rec("", "RMM Agent", "1", "h1", "Windows")
	a.SoftwareType = "application"
	af := &appsFake{total: 1, pages: [][]app{{a}}, before: map[string]int{"RMM Agent": 40}}
	f.routes[appsRoute] = af.handler
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SeenBefore != 0 || rep.Reasons[ReasonNoVendor] != 1 || rep.ByType != 0 || len(af.filters) != 1 {
		t.Fatalf("rep = %+v filters = %v", rep, af.filters)
	}
}

func TestASuspiciousAppIsNeverOnlyACount(t *testing.T) {
	f, c := newFake(t)
	a := rec("Acme", "Helper", "1", "h1", "Windows")
	a.IsSuspicious = true
	b := rec("Acme", "Helper", "1", "", "Windows")
	b.IsSuspicious = true
	af := &appsFake{total: 2, pages: [][]app{{a, b}}, before: map[string]int{"Helper": 3}}
	f.routes[appsRoute] = af.handler
	rep, err := c.NewApps(context.Background(), time.Now(), NewAppsOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.SuspiciousKnown) != 1 || rep.SuspiciousKnown[0].Suspicious != 1 || rep.SuspiciousKnown[0].SuspiciousNoHost != 1 {
		t.Fatalf("rep = %+v", rep)
	}
}

func TestAVendoredAppIsOneAppWhateverItsTypeLabels(t *testing.T) {
	x := rec("Acme", "Tool", "1", "h1", "Windows")
	y := rec("Acme", "Tool", "1", "h2", "Windows")
	y.SoftwareType = "application"
	if got := summarise([]app{x, y}); len(got) != 1 || got[0].Hosts != 2 {
		t.Fatalf("split: %+v", got)
	}
}
