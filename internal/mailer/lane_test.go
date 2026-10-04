package mailer

import (
	"strings"
	"testing"
)

func env(pairs ...string) func(string) (string, bool) {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func wasLane(to, allow string, lookup func(string) (string, bool)) Lane {
	return Lane{
		Name: "was", ToVar: "WAS_TO", AllowVar: "WAS_ALLOW_TO",
		To: to, Allow: allow, Operator: "ops@example.com", Lookup: lookup,
	}
}

// ─── fail closed ────────────────────────────────────────────────────────────

func TestAnUnsetAllowlistRefusesAndDoesNotBorrowAnother(t *testing.T) {
	// The reason this type exists. CheckAllowed falls back to DIGEST_TO when
	// its allowlist is empty, which for a second audience means the
	// application-security report silently goes to the infrastructure list -
	// as a SUCCESSFUL send. A report that does not go out is an inconvenience;
	// one that reaches the wrong distribution list cannot be recalled.
	_, err := wasLane("dev@example.com", "", nil).Resolve(false)
	if err == nil {
		t.Fatal("an unset allowlist was accepted")
	}
	if !strings.Contains(err.Error(), "WAS_ALLOW_TO") {
		t.Errorf("the error does not name the variable to edit: %v", err)
	}
	if !strings.Contains(err.Error(), "does NOT fall back") {
		t.Errorf("the error does not rule out the fallback: %v", err)
	}
}

func TestApproveDoesNotBypassAnUnsetAllowlist(t *testing.T) {
	// --approve means a human reviewed a draft and accepted an unusual
	// recipient. An empty list is a misconfiguration; there is nothing to
	// have reviewed.
	if _, err := wasLane("dev@example.com", "", nil).Resolve(true); err == nil {
		t.Error("--approve bypassed an unset allowlist")
	}
}

func TestNoRecipientsIsRefusedRatherThanDefaulted(t *testing.T) {
	_, err := wasLane("", "dev@example.com", nil).Resolve(false)
	if err == nil || !strings.Contains(err.Error(), "WAS_TO") {
		t.Errorf("err = %v, want one naming WAS_TO", err)
	}
}

func TestARecipientOutsideTheListIsRefusedUntilApproved(t *testing.T) {
	l := wasLane("dev@example.com,outsider@elsewhere.example", "dev@example.com", nil)

	if _, err := l.Resolve(false); err == nil {
		t.Fatal("an outside recipient was accepted")
	} else if !strings.Contains(err.Error(), "outsider@elsewhere.example") {
		t.Errorf("the error does not name who: %v", err)
	}
	if _, err := l.Resolve(true); err != nil {
		t.Errorf("--approve did not permit a reviewed one-off: %v", err)
	}
}

func TestAMalformedAddressIsRefusedEvenWithApprove(t *testing.T) {
	// Approving a recipient you cannot read is not approval.
	l := wasLane("dev@example.com,not an address", "dev@example.com", nil)
	if _, err := l.Resolve(true); err == nil {
		t.Error("a malformed address survived --approve")
	}
}

func TestTheOperatorIsAlwaysPermitted(t *testing.T) {
	// The escalation path. A lane that cannot reach a human fails silently.
	l := wasLane("ops@example.com", "dev@example.com", nil)
	if _, err := l.Resolve(false); err != nil {
		t.Errorf("the operator was refused: %v", err)
	}
}

func TestMatchingIsCaseInsensitive(t *testing.T) {
	l := wasLane("Dev@Example.COM", "dev@example.com", nil)
	if _, err := l.Resolve(false); err != nil {
		t.Errorf("case difference refused a listed recipient: %v", err)
	}
}

// ─── references between lists ───────────────────────────────────────────────

func TestOneListCanBuildOnAnother(t *testing.T) {
	// PT_ALLOW_TO=$VM_ALLOW_TO,extra@example.com
	lookup := env("VM_ALLOW_TO", "alice@example.com,bob@example.com")
	got, err := ExpandAllow("PT_ALLOW_TO", "$VM_ALLOW_TO,carol@example.com", lookup)
	if err != nil {
		t.Fatalf("ExpandAllow: %v", err)
	}
	want := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestBracedReferencesWork(t *testing.T) {
	lookup := env("VM_ALLOW_TO", "alice@example.com")
	got, err := ExpandAllow("PT_ALLOW_TO", "${VM_ALLOW_TO},bob@example.com", lookup)
	if err != nil || len(got) != 2 {
		t.Errorf("got %v, err %v", got, err)
	}
}

func TestSomebodyInheritedTwiceIsMailedOnce(t *testing.T) {
	lookup := env(
		"A_ALLOW_TO", "alice@example.com,bob@example.com",
		"B_ALLOW_TO", "bob@example.com,carol@example.com",
	)
	got, err := ExpandAllow("C_ALLOW_TO", "$A_ALLOW_TO,$B_ALLOW_TO", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("got %v, want three distinct addresses", got)
	}
}

func TestAnUnsetReferenceIsRefusedNotTreatedAsEmpty(t *testing.T) {
	// Shell expansion of an undefined variable yields nothing, silently. On a
	// recipient list that is the worst available behaviour: a typo quietly
	// removes everyone inherited through it, and the error a human eventually
	// sees names the RECIPIENTS rather than the typo that removed them - so
	// they go looking in the wrong place.
	lookup := env("VM_ALLOW_TO", "alice@example.com")
	_, err := ExpandAllow("PT_ALLOW_TO", "$VM_ALLOW_TOO,carol@example.com", lookup)
	if err == nil {
		t.Fatal("an unset reference expanded to nothing instead of failing")
	}
	if !strings.Contains(err.Error(), "VM_ALLOW_TOO") {
		t.Errorf("the error does not name the missing variable: %v", err)
	}
}

func TestAReferenceCycleIsCaught(t *testing.T) {
	lookup := env(
		"A_ALLOW_TO", "$B_ALLOW_TO",
		"B_ALLOW_TO", "$A_ALLOW_TO",
	)
	_, err := ExpandAllow("A_ALLOW_TO", "$B_ALLOW_TO", lookup)
	if err == nil {
		t.Fatal("a reference cycle did not terminate with an error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("err = %v, want it to name the cycle", err)
	}
}

func TestDeepNestingIsBounded(t *testing.T) {
	lookup := env(
		"L1", "$L2", "L2", "$L3", "L3", "$L4",
		"L4", "$L5", "L5", "$L6", "L6", "$L7",
		"L7", "deep@example.com",
	)
	if _, err := ExpandAllow("TOP", "$L1", lookup); err == nil {
		t.Error("nesting beyond the limit was accepted")
	}
}

func TestAReferenceWithNoResolverIsRefused(t *testing.T) {
	// Lookup nil must not mean "$VM_ALLOW_TO is a literal address".
	_, err := wasLane("dev@example.com", "$VM_ALLOW_TO", nil).Resolve(false)
	if err == nil {
		t.Error("a reference was accepted with no way to resolve it")
	}
}

func TestReferencesResolveThroughLaneResolve(t *testing.T) {
	// End to end: the lane, not just ExpandAllow.
	lookup := env("VM_ALLOW_TO", "alice@example.com,bob@example.com")
	l := wasLane("bob@example.com,carol@example.com",
		"$VM_ALLOW_TO,carol@example.com", lookup)

	to, err := l.Resolve(false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(to) != 2 {
		t.Errorf("to = %v", to)
	}
}

func TestWildcardsAndPatternsAreRefusedByName(t *testing.T) {
	// A reference names ONE other list. There is deliberately no way to say
	// "every allowlist": a pattern would mean that adding an unrelated lane's
	// list later silently widens every audience that matched it, and nobody
	// would revisit those lists to notice.
	lookup := env("VM_ALLOW_TO", "alice@example.com")
	for _, bad := range []string{
		"$*_ALLOW_TO,a@example.com",
		"${*},a@example.com",
		"$*,a@example.com",
		"$VM_*,a@example.com",
		"$ALLOW-TO,a@example.com",
	} {
		_, err := ExpandAllow("L_ALLOW_TO", bad, lookup)
		if err == nil {
			t.Errorf("%q was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "wildcard") {
			t.Errorf("%q: error does not explain the rule: %v", bad, err)
		}
	}
}

func TestABareDollarIsAnErrorNotSilentlyDropped(t *testing.T) {
	// It must not vanish, leaving a shorter list than the operator wrote, and
	// it must not be reported as a bad ADDRESS - that sends a reader to look
	// at their address list rather than at their typo.
	lookup := env("X", "a@example.com")
	if _, err := ExpandAllow("L", "$,a@example.com", lookup); err == nil {
		t.Error("a bare $ was accepted")
	}
}

// ─── the copy-paste check ───────────────────────────────────────────────────

func TestAListCopiedFromAnotherLaneIsFlagged(t *testing.T) {
	// Not an error: two lanes legitimately share people. But a WAS list whose
	// recipients are ENTIRELY the VM audience almost certainly means WAS_TO
	// was copied from DIGEST_TO and never edited, which is the
	// misconfiguration this whole split exists to catch.
	l := wasLane("alice@example.com,bob@example.com", "x", nil)
	note := l.CrossCheck("vm", "alice@example.com,bob@example.com,carol@example.com")
	if note == "" {
		t.Error("a fully-overlapping recipient list was not flagged")
	}
	if !strings.Contains(note, "WAS_TO") {
		t.Errorf("the note does not name the variable: %q", note)
	}
}

func TestPartialOverlapIsNotFlagged(t *testing.T) {
	// An operator on both lists is normal and must not produce a warning that
	// trains people to ignore it.
	l := wasLane("alice@example.com,dev@example.com", "x", nil)
	if note := l.CrossCheck("vm", "alice@example.com,bob@example.com"); note != "" {
		t.Errorf("partial overlap was flagged: %q", note)
	}
}
