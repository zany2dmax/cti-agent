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
