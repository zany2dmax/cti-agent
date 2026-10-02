package version

import (
	"strings"
	"testing"
)

func TestAnUnstampedBuildSaysSoRatherThanGuessing(t *testing.T) {
	// A confident wrong answer is worse than an admitted unknown here. The
	// whole point of this package is to be trusted during an incident, and a
	// binary that claims a version it cannot support destroys that in one
	// reading.
	i := Info{Tag: Unknown, Commit: Unknown, Built: Unknown, Stamped: false}
	s := i.String()
	if !strings.Contains(s, "not stamped by the installer") {
		t.Errorf("an unstamped build did not admit it: %q", s)
	}
	if i.Stamped {
		t.Error("Stamped should be false when nothing was injected")
	}
}

func TestADirtyBuildIsLoudAboutIt(t *testing.T) {
	// A binary built from a dirty tree cannot be reproduced from its commit,
	// so "it matches the tag" stops being a useful claim. Quiet is wrong.
	i := Info{Tag: "v1.0", Commit: "abcdef0123456789", Dirty: true, Built: Unknown, Stamped: true}
	if s := i.String(); !strings.Contains(s, "DIRTY") {
		t.Errorf("a dirty build did not say so: %q", s)
	}
	clean := Info{Tag: "v1.0", Commit: "abcdef0123456789", Built: Unknown, Stamped: true}
	if s := clean.String(); strings.Contains(s, "DIRTY") {
		t.Errorf("a clean build was marked dirty: %q", s)
	}
}

func TestTheShortCommitIsTwelveNotSeven(t *testing.T) {
	// Seven is the git default and this repository will outlive the point
	// where it is comfortably unique. A truncated hash that collides while
	// somebody is deciding whether prod is up to date is a bad day.
	i := Info{Commit: "abcdef0123456789abcdef"}
	if got := i.Short(); got != "abcdef012345" {
		t.Errorf("Short() = %q, want 12 characters", got)
	}
	// A short or absent commit must pass through rather than panic on a slice.
	for _, c := range []string{Unknown, "abc", ""} {
		if got := (Info{Commit: c}).Short(); got != c {
			t.Errorf("Short(%q) = %q, want it unchanged", c, got)
		}
	}
}

func TestAStaleBinaryIsNamedAsStale(t *testing.T) {
	// The case this exists for: a binary left behind by an older install
	// sitting beside newer ones. That is what a partial install produces, and
	// no amount of "Installed" output reveals it - we had exactly this when
	// cti-mailer was missing from a box that reported a clean install.
	i := Info{Commit: "aaaaaaaaaaaaaaaa"}
	msg := i.Mismatch("bbbbbbbbbbbbbbbb")
	if msg == "" {
		t.Fatal("a binary that predates the install was not flagged")
	}
	if !strings.Contains(msg, "aaaaaaaaaaaa") || !strings.Contains(msg, "bbbbbbbbbbbb") {
		t.Errorf("the message does not name both commits: %q", msg)
	}
	if !strings.Contains(msg, "predates") {
		t.Errorf("the message does not explain the consequence: %q", msg)
	}
}

func TestMatchingBuildsAreQuiet(t *testing.T) {
	// Including the abbreviated case: the installer records a full hash, the
	// binary may carry either, and reporting those as a mismatch would cry
	// wolf on every single run.
	full := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct{ binary, recorded string }{
		{full, full},
		{full[:12], full},
		{full, full[:12]},
	} {
		if msg := (Info{Commit: tc.binary}).Mismatch(tc.recorded); msg != "" {
			t.Errorf("binary=%s recorded=%s reported a mismatch: %q",
				tc.binary[:8], tc.recorded[:8], msg)
		}
	}
}

func TestNothingToCompareAgainstIsNotAMismatch(t *testing.T) {
	// An older install recorded no commit at all. That is unknown, not wrong,
	// and warning about it would train people to ignore the warning that
	// matters.
	for _, recorded := range []string{"", "   ", Unknown} {
		if msg := (Info{Commit: "aaaaaaaaaaaa"}).Mismatch(recorded); msg != "" {
			t.Errorf("recorded=%q produced a mismatch: %q", recorded, msg)
		}
	}
	if msg := (Info{Commit: Unknown}).Mismatch("aaaaaaaaaaaa"); msg != "" {
		t.Errorf("an unknown binary commit produced a mismatch: %q", msg)
	}
}

func TestGetNeverReturnsEmptyFields(t *testing.T) {
	// Whatever the build circumstances, every field must read as something a
	// human can interpret. An empty string in a --check table looks like a
	// rendering bug rather than a missing value.
	i := Get()
	if i.Tag == "" || i.Commit == "" || i.Built == "" {
		t.Errorf("Get returned an empty field: %+v", i)
	}
	if i.String() == "" {
		t.Error("String() is empty")
	}
}
