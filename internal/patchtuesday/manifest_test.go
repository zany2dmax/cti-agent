package patchtuesday

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func manifestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatalf("state dir: %v", err)
	}
	return home
}

func TestManifestRoundTrips(t *testing.T) {
	home := manifestHome(t)
	path := ManifestPath(home, 2026, time.September)
	if !strings.HasSuffix(path, "state/patchtuesday-2026-09.json") {
		t.Errorf("ManifestPath = %q", path)
	}

	in := Manifest{
		Month:     MonthKey(2026, time.September),
		WrittenAt: time.Now().Truncate(time.Second),
		CVEs:      []string{"CVE-2026-2222", "CVE-2026-1111"},
		QIDs:      []int{92440, 92439},
		Hosts:     452,
	}
	if err := WriteManifest(path, in); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	out, ok, err := LoadManifest(path)
	if err != nil || !ok {
		t.Fatalf("LoadManifest: ok=%v err=%v", ok, err)
	}
	if out.Month != "2026-09" || out.Hosts != 452 {
		t.Errorf("month=%q hosts=%d", out.Month, out.Hosts)
	}
	// Sorted on write, so two runs of the same month produce the same file and
	// a diff between them means something changed.
	if got := strings.Join(out.CVEs, ","); got != "CVE-2026-1111,CVE-2026-2222" {
		t.Errorf("CVEs not sorted on write: %v", out.CVEs)
	}
	if out.QIDs[0] != 92439 {
		t.Errorf("QIDs not sorted on write: %v", out.QIDs)
	}
	if out.Sent {
		t.Error("a freshly written manifest must not claim the email went out")
	}
}

func TestManifestIsPrivateAndWrittenAtomically(t *testing.T) {
	home := manifestHome(t)
	path := ManifestPath(home, 2026, time.September)
	if err := WriteManifest(path, Manifest{Month: "2026-09"}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
	// No .tmp left behind: a reader scanning state/ should not find two files
	// claiming to describe the same month.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file survived: %s", e.Name())
		}
	}
}

func TestAMissingManifestIsNotAnErrorButACorruptOneIs(t *testing.T) {
	home := manifestHome(t)
	path := ManifestPath(home, 2026, time.September)

	_, ok, err := LoadManifest(path)
	if ok || err != nil {
		t.Errorf("a month with no manifest: ok=%v err=%v; want false, nil", ok, err)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := LoadManifest(path); err == nil {
		t.Error("a corrupt manifest must be an error - acting on half a CVE " +
			"list means holding back an arbitrary subset of the release")
	}

	// And no FLEET_HOME means no manifest, not a path in the working
	// directory.
	if p := ManifestPath("", 2026, time.September); p != "" {
		t.Errorf("ManifestPath with no home = %q, want empty", p)
	}
	if _, ok, err := LoadManifest(""); ok || err != nil {
		t.Errorf("LoadManifest(\"\"): ok=%v err=%v", ok, err)
	}
}

// THE safety property of the whole feature. A manifest from a run whose email
// never went out must not silence the daily: the result would be CVEs in no
// email at all, from either lane, with nothing anywhere saying so.
func TestAnUnsentManifestHoldsBackNothing(t *testing.T) {
	m := Manifest{Month: "2026-09", CVEs: []string{"CVE-2026-1111", "CVE-2026-2222"},
		Sent: false}
	found := []string{"CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"}

	keep, held := Held(found, []Manifest{m})
	if len(held) != 0 {
		t.Errorf("held %v from a manifest that was never sent", held)
	}
	if len(keep) != 3 {
		t.Errorf("keep = %v, want all three", keep)
	}
	if HoldNote(held) != "" {
		t.Errorf("nothing held, so nothing to say: %q", HoldNote(held))
	}

	// Marked sent, the same manifest holds its own CVEs and nothing else.
	m.Sent = true
	keep, held = Held(found, []Manifest{m})
	if len(keep) != 1 || keep[0] != "CVE-2026-3333" {
		t.Errorf("keep = %v, want only CVE-2026-3333", keep)
	}
	if held["CVE-2026-1111"] != "2026-09" || held["CVE-2026-2222"] != "2026-09" {
		t.Errorf("held = %v; each CVE should name the month that covered it", held)
	}
	note := HoldNote(held)
	for _, want := range []string{"2 CVE(s) held back", "2 from 2026-09"} {
		if !strings.Contains(note, want) {
			t.Errorf("HoldNote %q missing %q", note, want)
		}
	}
}

func TestHeldIsCaseAndSpaceInsensitiveAndKeepsOrder(t *testing.T) {
	m := Manifest{Month: "2026-09", Sent: true,
		CVEs: []string{" cve-2026-1111 ", "CVE-2026-2222"}}
	found := []string{"CVE-2026-9999", "CVE-2026-1111", "CVE-2026-0001"}

	keep, held := Held(found, []Manifest{m})
	if len(held) != 1 || held["CVE-2026-1111"] == "" {
		t.Errorf("held = %v; a lowercase, padded entry in the file still covers "+
			"the CVE", held)
	}
	// Order preserved: the caller sorted these, and a report whose rows move
	// around between runs cannot be diffed against yesterday's.
	if strings.Join(keep, ",") != "CVE-2026-9999,CVE-2026-0001" {
		t.Errorf("keep = %v, want the caller's order", keep)
	}
}

func TestMarkSentIsIdempotentAndRefusesWhatIsNotThere(t *testing.T) {
	home := manifestHome(t)
	path := ManifestPath(home, 2026, time.September)

	if err := MarkSent(path, time.Now()); err == nil {
		t.Error("marking a manifest that does not exist should be an error, " +
			"not a silent success that authorises suppression")
	}

	if err := WriteManifest(path, Manifest{Month: "2026-09",
		CVEs: []string{"CVE-2026-1111"}}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	first := time.Now().Truncate(time.Second)
	if err := MarkSent(path, first); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	m, _, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if !m.Sent || m.SentAt.IsZero() {
		t.Errorf("sent=%v sentAt=%v", m.Sent, m.SentAt)
	}
	if len(m.CVEs) != 1 {
		t.Errorf("marking sent lost the CVE list: %v", m.CVEs)
	}

	// A re-run of the runner must not fail, and must not move the timestamp:
	// the first send is the one the daily's behaviour is keyed to.
	if err := MarkSent(path, first.Add(time.Hour)); err != nil {
		t.Errorf("MarkSent twice = %v, want nil", err)
	}
	again, _, _ := LoadManifest(path)
	if !again.SentAt.Equal(m.SentAt) {
		t.Errorf("SentAt moved on a second mark: %v -> %v", m.SentAt, again.SentAt)
	}
}

// Two months, not every manifest ever written. A September CVE arriving in
// December is not an echo of the September email - something is re-raising it,
// which is the daily's whole job.
func TestOnlyThisMonthAndLastMonthCanHoldAnythingBack(t *testing.T) {
	home := manifestHome(t)
	now := time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)

	write := func(y int, mo time.Month, cve string) {
		t.Helper()
		if err := WriteManifest(ManifestPath(home, y, mo), Manifest{
			Month: MonthKey(y, mo), CVEs: []string{cve}, Sent: true,
		}); err != nil {
			t.Fatalf("WriteManifest %s: %v", MonthKey(y, mo), err)
		}
	}
	write(2026, time.October, "CVE-2026-1010")   // this month
	write(2026, time.September, "CVE-2026-0909") // last month
	write(2026, time.July, "CVE-2026-0707")      // too old to silence anything

	ms, err := RecentManifests(home, now)
	if err != nil {
		t.Fatalf("RecentManifests: %v", err)
	}
	if len(ms) != 2 {
		t.Fatalf("loaded %d manifests, want 2 (this month and last)", len(ms))
	}
	_, held := Held([]string{"CVE-2026-1010", "CVE-2026-0909", "CVE-2026-0707"}, ms)
	if len(held) != 2 {
		t.Errorf("held = %v; July must not still be suppressing anything", held)
	}
	if _, ok := held["CVE-2026-0707"]; ok {
		t.Error("a CVE from three months ago was held back")
	}
	note := HoldNote(held)
	if !strings.Contains(note, "1 from 2026-09") || !strings.Contains(note, "1 from 2026-10") {
		t.Errorf("HoldNote should break down by month: %q", note)
	}
}

// January is the case a naive "month - 1" gets wrong, and getting it wrong
// means December's release quietly stops being suppressed on New Year's Day -
// or, worse, that a path is built for month 0.
func TestTheWindowCrossesTheYearBoundary(t *testing.T) {
	home := manifestHome(t)
	if err := WriteManifest(ManifestPath(home, 2025, time.December), Manifest{
		Month: MonthKey(2025, time.December), CVEs: []string{"CVE-2025-1212"},
		Sent: true,
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	now := time.Date(2026, time.January, 5, 6, 0, 0, 0, time.UTC)

	ms, err := RecentManifests(home, now)
	if err != nil {
		t.Fatalf("RecentManifests: %v", err)
	}
	_, held := Held([]string{"CVE-2025-1212"}, ms)
	if held["CVE-2025-1212"] != "2025-12" {
		t.Errorf("held = %v; December 2025 should still be in the window on "+
			"5 January 2026", held)
	}
}

// The 31st is the other date-arithmetic trap: AddDate(0,-1,0) from 31 March
// lands on 2 or 3 March, not in February at all, which would silently drop
// last month from the window for a few days each year.
func TestTheWindowIsNotBrokenByALongMonth(t *testing.T) {
	home := manifestHome(t)
	if err := WriteManifest(ManifestPath(home, 2026, time.February), Manifest{
		Month: MonthKey(2026, time.February), CVEs: []string{"CVE-2026-0202"},
		Sent: true,
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	now := time.Date(2026, time.March, 31, 6, 0, 0, 0, time.UTC)

	ms, err := RecentManifests(home, now)
	if err != nil {
		t.Fatalf("RecentManifests: %v", err)
	}
	_, held := Held([]string{"CVE-2026-0202"}, ms)
	if held["CVE-2026-0202"] != "2026-02" {
		t.Errorf("held = %v; February should be in the window on 31 March, but "+
			"AddDate(0,-1,0) from the 31st normalises into March", held)
	}
}

func TestAnUnreadableManifestIsReportedAndDecidesNothing(t *testing.T) {
	home := manifestHome(t)
	now := time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)
	// This month's is corrupt; last month's is fine and still usable.
	if err := os.WriteFile(ManifestPath(home, 2026, time.October),
		[]byte("{{{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteManifest(ManifestPath(home, 2026, time.September), Manifest{
		Month: MonthKey(2026, time.September), CVEs: []string{"CVE-2026-0909"},
		Sent: true,
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	ms, err := RecentManifests(home, now)
	if err == nil {
		t.Error("a corrupt manifest has to be reported, not swallowed")
	}
	if len(ms) != 1 {
		t.Fatalf("the readable manifest should still be returned, got %d", len(ms))
	}
	_, held := Held([]string{"CVE-2026-0909", "CVE-2026-1010"}, ms)
	if len(held) != 1 || held["CVE-2026-0909"] == "" {
		t.Errorf("held = %v; the corrupt file must decide nothing either way", held)
	}
}
