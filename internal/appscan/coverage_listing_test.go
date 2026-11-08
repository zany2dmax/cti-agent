package appscan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppListingKeepsNameAndURLApart(t *testing.T) {
	apps := []App{
		{ID: "1", Name: "Billing", URL: "https://www.billing.example.com/app"},
		{ID: "2", Name: "Shop https://brochure.example.com <-", URL: "https://evil.example.org/"},
	}
	sites := []Site{{Domain: "brochure.example.com"}, {Domain: "billing.example.com"}}
	l := NewAppListing(apps, sites, true, Owners{})
	if l.Format != AppListingFormat {
		t.Fatalf("format %q", l.Format)
	}
	if l.Apps[0].Host != "billing.example.com" || l.Apps[1].Host != "evil.example.org" {
		t.Fatalf("hosts come from the URL only: %+v", l.Apps)
	}
	if strings.Join(l.Unscanned, ",") != "brochure.example.com" {
		t.Fatalf("unscanned = %v, want brochure only (the name's URL scans nothing)", l.Unscanned)
	}
	b, err := json.Marshal(l)
	if err != nil || !strings.Contains(string(b), `"coverage":true`) {
		t.Fatalf("json %s %v", b, err)
	}
}

func TestAppListingWithoutSitesClaimsNoCoverage(t *testing.T) {
	l := NewAppListing([]App{{ID: "1", Name: "A", URL: "https://a.example.com"}}, nil, false, Owners{})
	if l.Coverage || len(l.Unscanned) != 0 {
		t.Fatalf("no website list must mean no coverage claim: %+v", l)
	}
	b, _ := json.Marshal(l)
	if !strings.Contains(string(b), `"unscanned":[]`) {
		t.Fatalf("unscanned must be [], not null: %s", b)
	}
}
