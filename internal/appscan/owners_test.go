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
	text, unowned, stale := OwnersSkeleton(apps, o)
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
