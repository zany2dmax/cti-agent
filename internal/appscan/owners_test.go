package appscan

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnersByIDThenName(t *testing.T) {
	o, problems, err := ParseOwners(strings.NewReader(`
# application | owner | component
id:123456         | Lead.One@example.com | Web Portal
Customer Portal   | two@example.com
Broken line
Other App         | not-an-email
id:123456         | three@example.com    # duplicate: later wins
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 3 {
		t.Errorf("problems = %v", problems)
	}
	if w, ok := o.For("123456", "Renamed App"); !ok || w.Email != "three@example.com" {
		t.Errorf("by id: %+v %v", w, ok)
	}
	if w, ok := o.For("", "customer portal"); !ok || w.Email != "two@example.com" || w.Component != "" {
		t.Errorf("by name: %+v %v", w, ok)
	}
	if _, ok := o.For("999", "Nobody's App"); ok {
		t.Error("an unlisted application found an owner")
	}
}

func TestAMissingOwnersFileIsAProblemNotAFailure(t *testing.T) {
	o, problems := LoadOwners(filepath.Join(t.TempDir(), "absent.txt"))
	if len(problems) != 1 || !strings.Contains(problems[0], "unassigned") {
		t.Errorf("problems = %v", problems)
	}
	if _, ok := o.For("1", "x"); ok {
		t.Error("an empty owners set found an owner")
	}
}

func TestTheSkeletonKeepsOwnersAndFlagsTheRest(t *testing.T) {
	o, problems, _ := ParseOwners(strings.NewReader(`
id:101          | lead@example.com | Web
Customer Portal | two@example.com
id:999          | gone@example.com
id:300          | OWNER@example.com
`))
	if len(problems) != 1 || !strings.Contains(problems[0], "no owner yet") {
		t.Errorf("an unedited placeholder must be refused: %v", problems)
	}
	apps := []App{
		{ID: "101", Name: "Portal", URL: "https://p.example.com"},
		{ID: "202", Name: "Customer Portal"},
		{ID: "300", Name: "New App"},
	}
	text, unowned, stale := OwnersSkeleton(apps, nil, o)
	for _, want := range []string{
		"id:101 | lead@example.com | Web    # Portal https://p.example.com",
		"id:202 | two@example.com    # Customer Portal",
		"id:300 | OWNER@example.com    # New App  <- no owner",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if len(unowned) != 1 || unowned[0].ID != "300" {
		t.Errorf("unowned %v", unowned)
	}
	if len(stale) != 1 || !strings.Contains(stale[0], "id:999") {
		t.Errorf("stale %v", stale)
	}
	// The skeleton parses back to the same owners.
	o2, _, err := ParseOwners(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if w, ok := o2.For("202", ""); !ok || w.Email != "two@example.com" {
		t.Errorf("round trip lost the name-keyed owner: %+v", w)
	}
}

func TestLiveWebsitesWithNoWebAppAreListedOnce(t *testing.T) {
	o, _, _ := ParseOwners(strings.NewReader("site:shop.example.net | web@example.com\nsite:gone.example.org | old@example.com\n"))
	apps := []App{{ID: "1", Name: "Portal", URL: "https://www.portal.example.com/login"}}
	sites := []Site{
		{Domain: "portal.example.com", Host: "www.portal.example.com"}, // scanned (www. ignored)
		{Domain: "shop.example.net", Host: "shop.example.net", URL: "https://shop.example.net/", Title: "Shop"},
		{Domain: "brochure.example.com", Host: "www.brochure.example.com"},
	}
	gap := Unscanned(sites, apps)
	if len(gap) != 2 || gap[0].Domain != "brochure.example.com" || gap[1].Domain != "shop.example.net" {
		t.Fatalf("gap %+v", gap)
	}
	text, _, stale := OwnersSkeleton(apps, sites, o)
	for _, want := range []string{"NOT SCANNED", "site:shop.example.net | web@example.com",
		"site:brochure.example.com | OWNER@example.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "site:portal.example.com") {
		t.Error("a scanned site was listed as not scanned")
	}
	if len(stale) != 1 || !strings.Contains(stale[0], "gone.example.org") {
		t.Errorf("a site line for a site no longer live should be stale: %v", stale)
	}
	o2, _, _ := ParseOwners(strings.NewReader(text))
	if w, ok := o2.ForSite("shop.example.net"); !ok || w.Email != "web@example.com" {
		t.Errorf("site line did not round-trip: %+v", w)
	}
}

func TestAStagingWebAppCanStandInForProduction(t *testing.T) {
	o, problems, _ := ParseOwners(strings.NewReader(`
id:500 | web@example.com | Web | covers=www.example.com, shop.example.com
id:600 | OWNER@example.com | covers=other.example.org
id:700 | web@example.com | covers=notahost
site:x.example.net | web@example.com | covers=y.example.net
`))
	if got := o.CoversFor("500", ""); len(got) != 2 || got[0] != "example.com" || got[1] != "shop.example.com" {
		t.Errorf("covers %v (www. is ignored)", got)
	}
	if w, _ := o.For("500", ""); w.Component != "Web" {
		t.Errorf("covers= was taken for the component: %+v", w)
	}
	if got := o.CoversFor("600", ""); len(got) != 1 {
		t.Errorf("covers= on a placeholder line must survive: %v", got)
	}
	want := map[string]bool{"covers=notahost": false, "site: line": false, "no owner yet": false}
	for _, p := range problems {
		for k := range want {
			if strings.Contains(p, k) {
				want[k] = true
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("no problem reported for %q: %v", k, problems)
		}
	}

	apps := []App{{ID: "500", Name: "Site (staging)", URL: "https://site-stg.wpenginepowered.com/"},
		{ID: "800", Name: "Shop", URL: "https://shop.example.com/"}}
	sites := []Site{{Domain: "example.com", Host: "www.example.com"}, {Domain: "shop.example.com", Host: "shop.example.com"},
		{Domain: "lonely.example.com", Host: "lonely.example.com"}}
	gap, proxied := Coverage(sites, apps, o)
	if len(gap) != 1 || gap[0].Domain != "lonely.example.com" {
		t.Errorf("gap %+v", gap)
	}
	if len(proxied) != 1 || proxied[0].Site.Domain != "example.com" || proxied[0].App.ID != "500" {
		t.Errorf("a directly scanned site must not be listed as via staging; proxied %+v", proxied)
	}
	text, _, _ := OwnersSkeleton(apps, sites, o)
	for _, w := range []string{"id:500 | web@example.com | Web | covers=example.com,shop.example.com",
		"Covered only through a stand-in", "example.com  via id:500"} {
		if !strings.Contains(text, w) {
			t.Errorf("skeleton missing %q:\n%s", w, text)
		}
	}
	o2, _, _ := ParseOwners(strings.NewReader(text))
	if len(o2.CoversFor("500", "")) != 2 {
		t.Error("covers= did not survive regenerating the file")
	}
}

func TestStagingLookingHostsAreFlagged(t *testing.T) {
	for _, u := range []string{"https://site.wpenginepowered.com/", "https://staging.example.com", "https://app-dev.example.com",
		"https://uat.example.com/login", "https://x.kinsta.cloud"} {
		if !stagingHint(u) {
			t.Errorf("%s should be flagged", u)
		}
	}
	for _, u := range []string{"https://www.example.com", "https://developer.example.com", "https://testimonials.example.com"} {
		if stagingHint(u) {
			t.Errorf("%s flagged as staging", u)
		}
	}
	o, _, _ := ParseOwners(strings.NewReader(""))
	text, _, _ := OwnersSkeleton([]App{{ID: "1", Name: "x", URL: "https://x.wpenginepowered.com"}}, nil, o)
	if !strings.Contains(text, "add | covers=") {
		t.Errorf("no prompt for an unrecorded staging host:\n%s", text)
	}
}
