package jira

import (
	"strings"
	"testing"
	"time"
)

func stateWith(hosts []string, qids []string, kept bool) *ExposureState {
	s := &ExposureState{
		CVE: "CVE-2026-85880", HostCount: len(hosts),
		HostsHash: HostsHashOf(hosts), QIDs: sortedCopy(qids), HostsKept: kept,
	}
	if kept {
		s.Hosts = sortedCopy(hosts)
	}
	return s
}

func finding(hosts, qids []string) Finding {
	return Finding{CVE: "CVE-2026-85880", Hosts: hosts, QIDs: qids, KEV: true, Severity: 5}
}

func TestAnUnchangedSetSaysNothing(t *testing.T) {
	// The whole anti-noise requirement. A daily "still 441 hosts" comment is
	// the ticket storm in a different costume.
	hosts := []string{"a.example.com", "b.example.com"}
	d := DiffExposure(stateWith(hosts, []string{"1"}, true), finding(hosts, []string{"1"}), now)
	if d.Material() {
		t.Errorf("an unchanged set was reported as material: %+v", d)
	}
}

func TestOrderAndCaseAreNotDrift(t *testing.T) {
	// The scanner promises no ordering and is inconsistent about case.
	// Without normalising, the same hosts back in a different sequence would
	// comment every single morning - and the comments would be ignored
	// within a week.
	prev := stateWith([]string{"A.example.com", "b.example.com"}, []string{"1", "2"}, true)
	f := finding([]string{"b.EXAMPLE.com", "a.example.com"}, []string{"2", "1"})
	d := DiffExposure(prev, f, now)
	if d.Material() {
		t.Errorf("reordered, recased hosts were reported as drift: new=%v gone=%v",
			d.NewHosts, d.GoneHosts)
	}
	if HostsHashOf([]string{"a", "b"}) != HostsHashOf([]string{"B", "A"}) {
		t.Error("the host hash is order- or case-sensitive")
	}
}

func TestGrowthIsMaterialAndNamesTheNewHosts(t *testing.T) {
	prev := stateWith([]string{"a.example.com"}, []string{"1"}, true)
	f := finding([]string{"a.example.com", "b.example.com"}, []string{"1"})
	d := DiffExposure(prev, f, now)
	if !d.Material() {
		t.Fatal("a new host was not material")
	}
	if len(d.NewHosts) != 1 || d.NewHosts[0] != "b.example.com" {
		t.Errorf("NewHosts = %v, want [b.example.com]", d.NewHosts)
	}
	c := DriftComment(d, f, "x.csv", now)
	if !strings.Contains(c, "b.example.com") {
		t.Errorf("comment does not name the new host: %q", c)
	}
	if !strings.Contains(c, "1 -> 2 hosts") {
		t.Errorf("comment does not lead with the change: %q", c)
	}
}

func TestShrinkingAloneIsNotMaterial(t *testing.T) {
	// Sets drift downward constantly as machines reboot, agents drop off and
	// scans complete partially. Commenting on every dip means a comment most
	// mornings, which is the thing the operator ruled out.
	prev := stateWith([]string{"a.example.com", "b.example.com", "c.example.com"}, []string{"1"}, true)
	f := finding([]string{"a.example.com"}, []string{"1"})
	d := DiffExposure(prev, f, now)
	if d.Material() {
		t.Error("a shrinking set triggered a comment on its own")
	}
	if len(d.GoneHosts) != 2 {
		t.Errorf("GoneHosts = %v, want 2", d.GoneHosts)
	}
}

func TestRemediatedHostsAreReportedWhenSomethingElseEarnsAComment(t *testing.T) {
	// Progress is worth seeing; it is just not worth an interruption. So it
	// rides along rather than triggering.
	prev := stateWith([]string{"a.example.com", "b.example.com"}, []string{"1"}, true)
	f := finding([]string{"a.example.com", "c.example.com"}, []string{"1"})
	d := DiffExposure(prev, f, now)
	if !d.Material() {
		t.Fatal("a new host should make this material")
	}
	c := DriftComment(d, f, "x.csv", now)
	if !strings.Contains(c, "c.example.com") {
		t.Error("comment omits the new host")
	}
	if !strings.Contains(c, "b.example.com") || !strings.Contains(c, "no longer detected") {
		t.Errorf("comment omits the remediated host: %q", c)
	}
}

func TestReachingZeroIsMaterialAndSaysItCanBeClosed(t *testing.T) {
	// The only good news this lane produces, and the signal IT needs.
	prev := stateWith([]string{"a.example.com", "b.example.com"}, []string{"1"}, true)
	f := finding(nil, []string{"1"})
	d := DiffExposure(prev, f, now)
	if !d.Resolved || !d.Material() {
		t.Fatalf("reaching zero was not material: %+v", d)
	}
	c := DriftComment(d, f, "", now)
	if !strings.Contains(c, "No detections remain") || !strings.Contains(c, "can be closed") {
		t.Errorf("the all-clear does not say it can be closed: %q", c)
	}
}

func TestGoingFromZeroToZeroIsNotAnAllClear(t *testing.T) {
	// A ticket already at zero must not announce the all-clear every run.
	prev := stateWith(nil, []string{"1"}, true)
	d := DiffExposure(prev, finding(nil, []string{"1"}), now)
	if d.Resolved {
		t.Error("zero -> zero was reported as newly resolved")
	}
	if d.Material() {
		t.Error("zero -> zero earned a comment")
	}
}

func TestANewQIDIsMaterialEvenWithTheSameHosts(t *testing.T) {
	// A second QID on the same boxes means a new detection path for the same
	// CVE, which changes what remediation has to cover.
	hosts := []string{"a.example.com"}
	d := DiffExposure(stateWith(hosts, []string{"1"}, true), finding(hosts, []string{"1", "2"}), now)
	if !d.Material() {
		t.Fatal("a new QID was not material")
	}
	if len(d.NewQIDs) != 1 || d.NewQIDs[0] != "2" {
		t.Errorf("NewQIDs = %v, want [2]", d.NewQIDs)
	}
}

func TestAFirstLookIsNotADiscovery(t *testing.T) {
	// No stored state means an older ticket, or one filed before state
	// existed. Announcing all 441 hosts as newly affected would be a lie told
	// loudly, on the day the feature shipped.
	d := DiffExposure(nil, finding([]string{"a.example.com", "b.example.com"}, []string{"1"}), now)
	if !d.FirstLook {
		t.Error("absent state was not flagged as a first look")
	}
	if d.Material() {
		t.Error("a first look earned a comment")
	}
	if len(d.NewHosts) != 0 {
		t.Errorf("a first look reported %d new hosts", len(d.NewHosts))
	}
}

func TestAnUnstoredHostListFallsBackToCountsAndSaysSo(t *testing.T) {
	// Past MaxPropertyHosts the list is dropped to stay inside Jira's 32KB
	// property limit. The comment must then compare totals and admit it
	// cannot name hosts, rather than listing the current set as if new.
	prev := stateWith([]string{"a.example.com"}, []string{"1"}, false)
	prev.HostCount = 900
	f := finding(make([]string, 950), []string{"1"})
	d := DiffExposure(prev, f, now)
	if !d.HostsUnknown {
		t.Fatal("a dropped host list was not flagged")
	}
	if !d.Material() {
		t.Fatal("growth in the totals was not material")
	}
	if len(d.NewHosts) != 0 {
		t.Error("hosts were named despite having nothing to compare against")
	}
	c := DriftComment(d, f, "x.csv", now)
	if !strings.Contains(c, "900 -> 950") {
		t.Errorf("comment does not give the totals: %q", c)
	}
	if !strings.Contains(c, "cannot be named") {
		t.Errorf("comment does not admit it cannot name hosts: %q", c)
	}
}

func TestAnUnstoredHostListIgnoresAShrink(t *testing.T) {
	prev := stateWith(nil, []string{"1"}, false)
	prev.HostCount = 900
	d := DiffExposure(prev, finding(make([]string, 850), []string{"1"}), now)
	if d.Material() {
		t.Error("a shrink in the totals triggered a comment")
	}
}

func TestStateDropsTheHostListOnlyWhenItIsTooBig(t *testing.T) {
	small := StateFrom(finding(make([]string, MaxPropertyHosts), []string{"1"}), "CR-1", now)
	if !small.HostsKept || len(small.Hosts) != MaxPropertyHosts {
		t.Errorf("a list at the limit was dropped: kept=%v n=%d", small.HostsKept, len(small.Hosts))
	}
	big := StateFrom(finding(make([]string, MaxPropertyHosts+1), []string{"1"}), "CR-1", now)
	if big.HostsKept || len(big.Hosts) != 0 {
		t.Errorf("a list over the limit was kept: kept=%v n=%d", big.HostsKept, len(big.Hosts))
	}
	if big.HostCount != MaxPropertyHosts+1 || big.HostsHash == "" {
		t.Error("the count and hash must survive even when the list does not")
	}
}

func TestACommentNamesAtMostTwentyHosts(t *testing.T) {
	// A comment listing 400 hosts is one nobody reads to the end, and the
	// full set is attached on the same update anyway.
	prev := stateWith([]string{"old.example.com"}, []string{"1"}, true)
	hosts := []string{"old.example.com"}
	for i := 0; i < 100; i++ {
		hosts = append(hosts, "new-"+itoa(i)+".example.com")
	}
	d := DiffExposure(prev, finding(hosts, []string{"1"}), now)
	c := DriftComment(d, finding(hosts, []string{"1"}), "x.csv", now)
	if n := strings.Count(c, "* new-"); n > MaxListedInComment {
		t.Errorf("comment lists %d hosts, limit %d", n, MaxListedInComment)
	}
	if !strings.Contains(c, "and 80 more") {
		t.Errorf("comment does not say how many were omitted: %q", c)
	}
	if !strings.Contains(c, "x.csv") {
		t.Error("comment does not point at the full list")
	}
}

func TestTheClosedTicketNoteDoesNotThreatenToReopen(t *testing.T) {
	// Somebody closed it deliberately. Software that reverses a human
	// decision nightly is software that gets switched off.
	c := ClosedButDetectedComment(finding([]string{"a.example.com"}, []string{"1"}), now)
	low := strings.ToLower(c)
	if !strings.Contains(low, "has not reopened") {
		t.Errorf("the note does not say it left the ticket alone: %q", c)
	}
	if !strings.Contains(low, "will not comment again") {
		t.Errorf("the note does not promise to stay quiet: %q", c)
	}
}

func TestStateFromRoundTripsThroughTheHash(t *testing.T) {
	f := finding([]string{"b.example.com", "a.example.com"}, []string{"2", "1"})
	st := StateFrom(f, "CR-1", now)
	if st.HostsHash != HostsHashOf(f.Hosts) {
		t.Error("stored hash does not match the finding")
	}
	if st.QIDs[0] != "1" {
		t.Errorf("QIDs were not sorted: %v", st.QIDs)
	}
	if st.TicketKey != "CR-1" {
		t.Errorf("TicketKey = %q", st.TicketKey)
	}
	var zero time.Time
	if st.UpdatedAt == zero {
		t.Error("UpdatedAt was not set")
	}
}
