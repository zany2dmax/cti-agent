package mailer

import (
	"strings"
	"testing"
)

func TestVMAllowReadsTheNewName(t *testing.T) {
	raw, note, err := VMAllow(env("VM_ALLOW_TO", "a@example.com"))
	if err != nil || raw != "a@example.com" || note != "" {
		t.Errorf("got %q %q %v", raw, note, err)
	}
}

func TestVMAllowStillReadsTheOldName(t *testing.T) {
	raw, note, err := VMAllow(env("FLEET_ALLOW_TO", "a@example.com"))
	if err != nil || raw != "a@example.com" {
		t.Fatalf("got %q %v", raw, err)
	}
	if !strings.Contains(note, "rename it to VM_ALLOW_TO") {
		t.Errorf("the old name must be called out, got %q", note)
	}
}

func TestVMAllowRefusesTwoDifferentLists(t *testing.T) {
	_, _, err := VMAllow(env("VM_ALLOW_TO", "a@example.com", "FLEET_ALLOW_TO", "a@example.com,b@example.com"))
	if err == nil || !strings.Contains(err.Error(), "delete the FLEET_ALLOW_TO line") {
		t.Errorf("err = %v", err)
	}
}

func TestVMAllowAcceptsTheSameListUnderBothNames(t *testing.T) {
	raw, note, err := VMAllow(env("VM_ALLOW_TO", "a@example.com, b@example.com", "FLEET_ALLOW_TO", "B@example.com,a@example.com"))
	if err != nil || raw != "a@example.com, b@example.com" || note == "" {
		t.Errorf("got %q %q %v", raw, note, err)
	}
}

func TestVMAllowTreatsEmptyAsUnset(t *testing.T) {
	// dev-run sets FLEET_ALLOW_TO="" so fleet.env cannot load one behind it.
	raw, note, err := VMAllow(env("VM_ALLOW_TO", "a@example.com", "FLEET_ALLOW_TO", " "))
	if err != nil || raw != "a@example.com" || note != "" {
		t.Errorf("got %q %q %v", raw, note, err)
	}
}

func TestLaneReferencesResolveUnderEitherName(t *testing.T) {
	// fleet.env still says FLEET_ALLOW_TO; a lane list written against the
	// new name must see it, and one written against the old name too.
	base := env("FLEET_ALLOW_TO", "a@example.com")
	vm, _, err := VMAllow(base)
	if err != nil {
		t.Fatal(err)
	}
	lookup := AllowLookup(base, vm)
	for _, ref := range []string{"$VM_ALLOW_TO", "$FLEET_ALLOW_TO"} {
		got, err := ExpandAllow("WAS_ALLOW_TO", ref+",b@example.com", lookup)
		if err != nil || len(got) != 2 {
			t.Errorf("%s: got %v, %v", ref, got, err)
		}
	}
}
