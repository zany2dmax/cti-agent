package mailer

import (
	"fmt"
	"strings"
)

// THE VM ALLOWLIST'S NAME
//
// The digest's recipient allowlist was FLEET_ALLOW_TO, named when the
// vulnerability digest was the only thing the fleet mailed. Each lane now
// has its own list - WAS_ALLOW_TO, DOM_ALLOW_TO - and "FLEET" read as if it
// covered all of them, which it never did. It is VM_ALLOW_TO, matching the
// other lanes and the "$VM_ALLOW_TO" references lane lists already use.
//
// FLEET_ALLOW_TO is still read, so an upgrade needs no edit. Both set to
// different values is refused: a security control with two possible values
// is one whose effective value somebody will guess wrong.

const (
	// VMAllowVar is the digest's recipient allowlist.
	VMAllowVar = "VM_ALLOW_TO"

	// LegacyAllowVar is its name before 1.3.1, still accepted.
	LegacyAllowVar = "FLEET_ALLOW_TO"
)

// VMAllow returns the digest allowlist's raw value. note is non-empty when
// the deprecated name was used, for the caller to log; err is set when both
// names are set and disagree.
func VMAllow(lookup func(string) (string, bool)) (raw, note string, err error) {
	vm, vmSet := lookup(VMAllowVar)
	legacy, legacySet := lookup(LegacyAllowVar)
	vm, legacy = strings.TrimSpace(vm), strings.TrimSpace(legacy)
	vmSet = vmSet && vm != ""
	legacySet = legacySet && legacy != ""

	switch {
	case vmSet && legacySet:
		if !sameList(vm, legacy) {
			return "", "", fmt.Errorf(
				"%s and %s are both set, to different lists. %s is the old "+
					"name for %s: delete the %s line from fleet.env",
				VMAllowVar, LegacyAllowVar, LegacyAllowVar, VMAllowVar, LegacyAllowVar)
		}
		return vm, fmt.Sprintf("%s is the old name for %s and is set to the "+
			"same list - delete the %s line from fleet.env",
			LegacyAllowVar, VMAllowVar, LegacyAllowVar), nil
	case legacySet:
		return legacy, fmt.Sprintf("%s is deprecated - rename it to %s in fleet.env",
			LegacyAllowVar, VMAllowVar), nil
	default:
		return vm, "", nil
	}
}

// AllowLookup wraps lookup so a lane list referencing either name -
// "$VM_ALLOW_TO" or the old "$FLEET_ALLOW_TO" - gets the VM allowlist
// VMAllow resolved, whichever name fleet.env actually sets.
func AllowLookup(lookup func(string) (string, bool), vmAllow string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == VMAllowVar || name == LegacyAllowVar {
			return vmAllow, strings.TrimSpace(vmAllow) != ""
		}
		return lookup(name)
	}
}

// sameList compares two address lists ignoring order, case and spacing.
func sameList(a, b string) bool {
	set := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, x := range SplitList(s) {
			m[strings.ToLower(x)] = true
		}
		return m
	}
	x, y := set(a), set(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}
