package domains

import (
	"strings"
	"testing"
)

func addrs() Lookup { return Lookup{Values: []string{"192.0.2.10"}} }

func websitesReport() Report {
	return Report{Now: now, Registrar: "godaddy", Results: []Result{
		{Entry: Entry{Name: "a.example"}, Web: []Web{
			{Host: "a.example", Addrs: addrs(), HTTPS: Fetch{Tried: true, Status: 200,
				FinalURL: "https://www.a.example/", Title: "  Home\n Page "}}}},
		// Apex has no records; www redirects to a.example. A redirect to
		// another domain, found on www.
		{Entry: Entry{Name: "b.example"}, Web: []Web{
			{Host: "b.example", Addrs: Lookup{Absent: true}},
			{Host: "www.b.example", Addrs: addrs(), HTTP: Fetch{Tried: true, Status: 200,
				FinalURL: "https://a.example/"}}}},
		{Entry: Entry{Name: "c.example"}, Web: []Web{
			{Host: "c.example", Addrs: addrs(), HTTPS: Fetch{Tried: true, Status: 200, Parked: "sedo"}}}},
		{Entry: Entry{Name: "d.example"}, Web: []Web{
			{Host: "d.example", Addrs: addrs(), HTTPS: Fetch{Tried: true, Status: 503}}}},
		{Entry: Entry{Name: "e.example"}, Web: []Web{
			{Host: "e.example", Addrs: Lookup{Absent: true}},
			{Host: "www.e.example", Addrs: Lookup{Absent: true}}}},
		{Entry: Entry{Name: "f.example"}, Web: []Web{
			{Host: "f.example", Addrs: Lookup{Err: "timeout"}}}},
		{Entry: Entry{Name: "g.example"}, Web: []Web{
			{Host: "g.example", Addrs: addrs(), HTTPS: Fetch{Tried: true, Status: 200,
				Registrar: "godaddy website builder"}}}},
		// Redirects to its own www: still its own live site.
		{Entry: Entry{Name: "h.example"}, Web: []Web{
			{Host: "h.example", Addrs: addrs(), HTTP: Fetch{Tried: true, Status: 200,
				FinalURL: "http://www.h.example/"}}}},
	}}
}

func TestClassifySite(t *testing.T) {
	want := map[string]siteClass{
		"a.example": siteLive, "b.example": siteRedirect, "c.example": siteParked,
		"d.example": siteBroken, "e.example": siteNone, "f.example": siteUnknown,
		"g.example": siteRegistrar, "h.example": siteLive,
	}
	for _, r := range websitesReport().Results {
		if got := classifySite(r).class; got != want[r.Entry.Name] {
			t.Errorf("%s: class %d, want %d", r.Entry.Name, got, want[r.Entry.Name])
		}
	}
}

func TestWebsitesComeFirstAndSayWhatEachDomainServes(t *testing.T) {
	b := websitesReport().Render()
	for _, s := range []string{
		"Websites: 3 domain(s) serve a live site, 1 redirect to another domain, " +
			"1 are parked, 1 have DNS but no working page, 1 have no website. 1 could not be checked.",
		"WEBSITES",
		"Live website (2)",
		`www.a.example · HTTP 200 · "Home Page"`,
		"www.h.example · HTTP 200 · HTTP only",
		"Redirects to another domain (1)",
		"→ a.example",
		"Parked or for sale (1)",
		"parked (sedo)",
		"Has DNS but no working page (1)",
		"apex HTTP 503",
		"No website (no address records) (1)",
		"Not checked (DNS lookup failed) (1)",
	} {
		if !strings.Contains(b.Text, s) {
			t.Errorf("text missing %q:\n%s", s, b.Text)
		}
	}
	if w, i := strings.Index(b.Text, "WEBSITES"), strings.Index(b.Text, "INVENTORY ("); w < 0 || w > i {
		t.Error("the WEBSITES section must come before the inventory")
	}
	if !strings.Contains(b.HTML, "WEBSITES") || !strings.Contains(b.HTML, "Live website (2)") {
		t.Error("HTML lacks the websites section")
	}
	if strings.Contains(b.HTML, "<a ") || strings.Contains(b.HTML, "https://") {
		t.Error("the websites section must not carry links or URLs")
	}
}

func TestWrapNames(t *testing.T) {
	got := wrapNames([]string{"aaaa.example", "bbbb.example", "cccc.example"}, 28)
	if len(got) != 2 || got[0] != "aaaa.example, bbbb.example," || got[1] != "cccc.example" {
		t.Errorf("wrapNames = %q", got)
	}
}
