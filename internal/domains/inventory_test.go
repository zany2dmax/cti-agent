package domains

import (
	"strings"
	"testing"
	"time"
)

// Synthetic names only. The real inventory is an operator file outside this
// public repository; nothing here may resemble it.

func TestParseInventory(t *testing.T) {
	in := `# a comment
example.com send
https://WWW.Example.NET/path   # pasted URL
example.org sned
example.com
not_a_domain
localhost
shop.example.com   sends
Example.EDU,send
`
	got, problems, err := ParseInventory(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Name: "example.com", Sends: true, Line: 2},
		{Name: "www.example.net", Line: 3},
		{Name: "example.org", Line: 4},
		{Name: "shop.example.com", Sends: true, Line: 8},
		{Name: "example.edu", Sends: true, Line: 9},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	joined := strings.Join(problems, "\n")
	for _, s := range []string{
		`line 4: unknown marker "sned"`,
		"line 5: example.com is already listed on line 2",
		`line 6: "not_a_domain" is not a domain name`,
		`line 7: "localhost" is not a domain name`,
	} {
		if !strings.Contains(joined, s) {
			t.Errorf("problems missing %q:\n%s", s, joined)
		}
	}
}

func TestNormalise(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.":                "example.com",
		"http://example.com:8080/x?y": "example.com",
		"example.com/path":            "example.com",
		"a-b.example.co.uk":           "a-b.example.co.uk",
	} {
		if got, ok := Normalise(in); !ok || got != want {
			t.Errorf("Normalise(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "com", "-a.example.com", "a..example.com",
		"ex ample.com", "exämple.com", strings.Repeat("a", 64) + ".com"} {
		if got, ok := Normalise(bad); ok {
			t.Errorf("Normalise(%q) accepted as %q", bad, got)
		}
	}
}

func TestCompare(t *testing.T) {
	inv := []Entry{
		{Name: "example.com"},
		{Name: "shop.example.com"},
		{Name: "elsewhere.example"},
		{Name: "badexample.com"}, // must NOT be covered by example.com
	}
	regs := []Registration{
		{Domain: "example.com", Status: "ACTIVE", Expires: time.Now()},
		{Domain: "forgotten.example", Status: "ACTIVE"},
	}
	c := Compare("godaddy", inv, regs)
	if c.Covered["shop.example.com"].Domain != "example.com" {
		t.Errorf("subdomain not covered by its parent: %+v", c.Covered)
	}
	if len(c.NotAtRegistrar) != 2 || c.NotAtRegistrar[0].Name != "elsewhere.example" ||
		c.NotAtRegistrar[1].Name != "badexample.com" {
		t.Errorf("NotAtRegistrar = %+v", c.NotAtRegistrar)
	}
	if len(c.NotInInventory) != 1 || c.NotInInventory[0].Domain != "forgotten.example" {
		t.Errorf("NotInInventory = %+v", c.NotInInventory)
	}
}

func TestCompareMostSpecificRegistration(t *testing.T) {
	regs := []Registration{{Domain: "example.com"}, {Domain: "shop.example.com"}}
	c := Compare("godaddy", []Entry{{Name: "a.shop.example.com"}}, regs)
	if c.Covered["a.shop.example.com"].Domain != "shop.example.com" {
		t.Errorf("matched %q, want the more specific registration", c.Covered["a.shop.example.com"].Domain)
	}
	// example.com covers nothing in the inventory, so it is unchecked.
	if len(c.NotInInventory) != 1 || c.NotInInventory[0].Domain != "example.com" {
		t.Errorf("NotInInventory = %+v", c.NotInInventory)
	}
}

func TestLapsedRegistrationsAreSetAside(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	inv := []Entry{{Name: "live.example"}, {Name: "old.example"}, {Name: "recent.example"}}
	regs := []Registration{
		{Domain: "live.example", Status: "ACTIVE", Expires: now.AddDate(1, 0, 0)},
		{Domain: "old.example", Status: "CANCELLED", Expires: time.Date(2020, 9, 8, 0, 0, 0, 0, time.UTC)},
		// Lapsed last week: maybe an accident, still recoverable - keep it.
		{Domain: "recent.example", Status: "EXPIRED", Expires: now.AddDate(0, 0, -7)},
		{Domain: "history.example", Status: "CANCELLED", Expires: time.Date(2013, 1, 11, 0, 0, 0, 0, time.UTC)},
		{Domain: "unlisted.example", Status: "ACTIVE", Expires: now.AddDate(1, 0, 0)},
	}
	c := Compare("godaddy", inv, regs)
	gone := c.SetAsideLapsed(now)

	if !gone["old.example"] || len(gone) != 1 {
		t.Errorf("gone = %v", gone)
	}
	if _, ok := c.Covered["old.example"]; ok {
		t.Error("a lapsed domain is still compared with the registrar")
	}
	if _, ok := c.Covered["recent.example"]; !ok {
		t.Error("a domain that lapsed last week was set aside - it may still be recoverable")
	}
	if len(c.Lapsed) != 1 || c.Lapsed[0].Entry.Name != "old.example" {
		t.Errorf("Lapsed = %+v", c.Lapsed)
	}
	if len(c.NotInInventory) != 1 || c.NotInInventory[0].Domain != "unlisted.example" || c.LapsedUnlisted != 1 {
		t.Errorf("NotInInventory = %+v, LapsedUnlisted = %d", c.NotInInventory, c.LapsedUnlisted)
	}
}
