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
