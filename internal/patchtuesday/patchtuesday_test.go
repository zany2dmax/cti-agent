package patchtuesday

import (
	"strings"
	"testing"
	"time"
)

func d(y int, m time.Month, day int) time.Time {
	return time.Date(y, m, day, 9, 0, 0, 0, time.UTC)
}

// ---------------------------------------------------------------- dates

func TestPatchTuesdayAgainstKnownReleases(t *testing.T) {
	// Checked against the Qualys review URLs, whose date path is Patch Tuesday
	// itself: .../2026/05/12/... and .../2026/09/08/...
	for _, tc := range []struct {
		y    int
		m    time.Month
		want int
	}{
		{2026, time.May, 12}, {2026, time.June, 9}, {2026, time.July, 14},
		{2026, time.August, 11}, {2026, time.September, 8},
	} {
		got := PatchTuesday(tc.y, tc.m)
		if got.Day() != tc.want {
			t.Errorf("%s %d: got day %d, want %d", tc.m, tc.y, got.Day(), tc.want)
		}
		if got.Weekday() != time.Tuesday {
			t.Errorf("%s %d: %s is a %s", tc.m, tc.y, got.Format("2006-01-02"), got.Weekday())
		}
	}
}

func TestPatchTuesdayIsAlwaysTheSecondTuesday(t *testing.T) {
	for y := 2026; y <= 2040; y++ {
		for m := time.January; m <= time.December; m++ {
			pt := PatchTuesday(y, m)
			if pt.Weekday() != time.Tuesday {
				t.Fatalf("%s %d is a %s", m, y, pt.Weekday())
			}
			if pt.Day() < 8 || pt.Day() > 14 {
				t.Fatalf("%s %d fell on day %d, outside 8..14", m, y, pt.Day())
			}
		}
	}
}

func TestReportDayIsNotTheSecondWednesday(t *testing.T) {
	// The bug this guards. "Second Wednesday" is the usual way to describe the
	// day after Patch Tuesday and it is wrong roughly one month in seven:
	// whenever the 1st is a Wednesday, the second Wednesday lands six days
	// BEFORE Patch Tuesday. A timer set that way wakes up before the content
	// exists. July 2026 is the case that exposed it.
	secondWed := func(y int, m time.Month) time.Time {
		f := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
		off := (int(time.Wednesday) - int(f.Weekday()) + 7) % 7
		return f.AddDate(0, 0, off+7)
	}
	if got := secondWed(2026, time.July); got.Day() != 8 {
		t.Fatalf("fixture wrong: second Wednesday of July 2026 is day %d", got.Day())
	}
	if ReportDay(2026, time.July).Day() != 15 {
		t.Errorf("ReportDay(July 2026) = %d, want 15 (Patch Tuesday 14 + 1)",
			ReportDay(2026, time.July).Day())
	}

	early := 0
	for y := 2026; y <= 2031; y++ {
		for m := time.January; m <= time.December; m++ {
			if secondWed(y, m).Before(PatchTuesday(y, m)) {
				early++
			}
		}
	}
	if early == 0 {
		t.Fatal("expected months where the second Wednesday precedes Patch Tuesday")
	}
	t.Logf("%d of 72 months would have fired early on a second-Wednesday timer", early)
}

func TestReportDayAlwaysWednesdayInTheTimerRange(t *testing.T) {
	// The systemd timer is OnCalendar=Wed *-*-09..15. Both halves of that have
	// to hold for every month or the lane silently never runs.
	for y := 2026; y <= 2040; y++ {
		for m := time.January; m <= time.December; m++ {
			r := ReportDay(y, m)
			if r.Weekday() != time.Wednesday {
				t.Fatalf("%s %d report day is a %s", m, y, r.Weekday())
			}
			if r.Day() < 9 || r.Day() > 15 {
				t.Fatalf("%s %d report day is %d, outside the timer's 09..15", m, y, r.Day())
			}
		}
	}
}

func TestTargetMonthRollsBackBeforeThisMonthsRelease(t *testing.T) {
	// Running on the 1st should report on last month, not on a Patch Tuesday
	// that has not happened.
	y, m := TargetMonth(d(2026, time.September, 1))
	if y != 2026 || m != time.August {
		t.Errorf("1 Sep -> %s %d, want August 2026", m, y)
	}
	// On the day itself, this month.
	y, m = TargetMonth(d(2026, time.September, 8))
	if y != 2026 || m != time.September {
		t.Errorf("8 Sep -> %s %d, want September 2026", m, y)
	}
	// The morning the email goes out.
	y, m = TargetMonth(d(2026, time.September, 9))
	if y != 2026 || m != time.September {
		t.Errorf("9 Sep -> %s %d, want September 2026", m, y)
	}
	// January rolls back across the year boundary.
	y, m = TargetMonth(d(2027, time.January, 2))
	if y != 2026 || m != time.December {
		t.Errorf("2 Jan 2027 -> %s %d, want December 2026", m, y)
	}
}

func TestReleasedGuardsAgainstSummarisingTheFuture(t *testing.T) {
	if Released(2026, time.September, d(2026, time.September, 7)) {
		t.Error("7 Sep: September's release had not happened yet")
	}
	if !Released(2026, time.September, d(2026, time.September, 8)) {
		t.Error("8 Sep IS Patch Tuesday")
	}
}

func TestParseMonth(t *testing.T) {
	y, m, err := ParseMonth("2026-08")
	if err != nil || y != 2026 || m != time.August {
		t.Errorf("got %d %s err=%v", y, m, err)
	}
	for _, bad := range []string{"2026", "08-2026", "2026-13", "August", ""} {
		if _, _, err := ParseMonth(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestQualysURLMatchesTheKnownPosts(t *testing.T) {
	// Verbatim from the May and September 2026 emails.
	want := "https://blog.qualys.com/vulnerabilities-threat-research/2026/05/12/" +
		"microsoft-patch-tuesday-may-2026-security-update-review"
	if got := QualysURL(2026, time.May); got != want {
		t.Errorf("\ngot  %s\nwant %s", got, want)
	}
	if got := QualysURL(2026, time.September); !strings.Contains(got, "2026/09/08/") {
		t.Errorf("September URL should use the 8th: %s", got)
	}
}

// ---------------------------------------------------------------- parsing

// Shaped on the real Qualys review: the phrasing, the QQL as a bare paragraph,
// and the category table are all as published.
const qualysFixture = `<html><body>
<p>This month's release addresses <b>137</b> vulnerabilities, including <b>30 </b>critical
and <b>103</b> important-severity<b> </b>vulnerabilities.</p>
<p>vulnerabilities.vulnerability: ( qid: 110525 or qid: 110526 or qid: 387304 )</p>
<p>In this month's updates, Microsoft has not addressed any publicly disclosed zero-day vulnerability.</p>
<p>Microsoft has addressed 128 vulnerabilities in Microsoft Edge (Chromium-based) that were patched earlier this month.</p>
<p>Microsoft Patch Tuesday, May edition, includes updates for vulnerabilities in Windows Hyper-V, .NET, M365 Copilot, Windows Kernel, and more.</p>
<p>The May 2026 Microsoft vulnerabilities are classified as follows:</p>
<table><tbody>
<tr><td><b>Vulnerability Category</b></td><td><b>Quantity</b></td><td><b>Severities</b></td></tr>
<tr><td>Spoofing Vulnerability</td><td>15</td><td>Critical: 4<br/>Important: 11</td></tr>
<tr><td>Remote Code Execution Vulnerability</td><td>31</td><td>Critical: 16<br/>Important: 15</td></tr>
</tbody></table>
<p>Adobe has released 10 security advisories to address 52 vulnerabilities in Adobe Premiere Pro and others. 27 of these are rated critical.</p>
<p>Affected: CVE-2026-1111, CVE-2026-2222 and CVE-2025-9999.</p>
</body></html>`

const bleepingFixture = `<html><body>
<h1>Microsoft September 2026 Patch Tuesday fixes 966 flaws, 2 zero-days</h1>
<p>Today is Microsoft's September 2026 Patch Tuesday, which fixes 966 flaws,
including two actively exploited zero-day vulnerabilities.</p>
<p>See CVE-2026-3333 for details.</p>
</body></html>`

func parsed(t *testing.T) *Digest {
	t.Helper()
	dg := &Digest{Year: 2026, Month: time.May, Sources: []Source{
		{Name: "Qualys security update review", URL: "q", Fetched: true,
			RawHTML: qualysFixture, Text: StripHTML(qualysFixture)},
		{Name: "BleepingComputer Patch Tuesday", URL: "b", Fetched: true,
			RawHTML: bleepingFixture, Text: StripHTML(bleepingFixture)},
	}}
	Parse(dg)
	return dg
}

func TestParseCounts(t *testing.T) {
	dg := parsed(t)
	if dg.Total != 137 {
		t.Errorf("Total = %d, want 137", dg.Total)
	}
	if dg.Critical != 30 {
		t.Errorf("Critical = %d, want 30", dg.Critical)
	}
	if dg.Important != 103 {
		t.Errorf("Important = %d, want 103", dg.Important)
	}
	if dg.EdgeFixes != 128 {
		t.Errorf("EdgeFixes = %d, want 128", dg.EdgeFixes)
	}
}

func TestParseZeroDaySentenceIsQuotedNotCounted(t *testing.T) {
	// "no zero-days" and "two exploited zero-days" are different facts and a
	// count cannot carry the difference. The vendor's sentence goes through
	// verbatim.
	dg := parsed(t)
	if !strings.Contains(strings.ToLower(dg.ZeroDayText), "zero-day") {
		t.Errorf("ZeroDayText = %q", dg.ZeroDayText)
	}
}

func TestParseQQLIsVerbatim(t *testing.T) {
	// The whole point of exposing it: someone pastes this into Qualys. A
	// paraphrase silently returns the wrong set.
	dg := parsed(t)
	if len(dg.SourceQQL) == 0 {
		t.Fatal("no QQL extracted")
	}
	want := "vulnerabilities.vulnerability: ( qid: 110525 or qid: 110526 or qid: 387304 )"
	found := false
	for _, q := range dg.SourceQQL {
		if q == want {
			found = true
		}
	}
	if !found {
		t.Errorf("QQL not extracted verbatim.\ngot  %q\nwant %q", dg.SourceQQL, want)
	}
}

func TestParseCategoryTable(t *testing.T) {
	dg := parsed(t)
	if len(dg.Categories) != 2 {
		t.Fatalf("got %d categories: %+v", len(dg.Categories), dg.Categories)
	}
	if dg.Categories[0].Name != "Spoofing Vulnerability" || dg.Categories[0].Quantity != 15 {
		t.Errorf("row 0 = %+v", dg.Categories[0])
	}
	if !strings.Contains(dg.Categories[1].Severities, "Critical: 16") {
		t.Errorf("severities lost: %q", dg.Categories[1].Severities)
	}
}

func TestParseHeaderRowIsNotACategory(t *testing.T) {
	for _, c := range parsed(t).Categories {
		if strings.Contains(c.Name, "Category") {
			t.Errorf("header row parsed as data: %+v", c)
		}
	}
}

func TestParseCollectsCVEsFromBothSources(t *testing.T) {
	dg := parsed(t)
	got := strings.Join(dg.CVEs, ",")
	for _, want := range []string{"CVE-2026-1111", "CVE-2026-2222", "CVE-2025-9999",
		"CVE-2026-3333"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s from %v", want, dg.CVEs)
		}
	}
}

func TestParseMissingNumbersStayZeroRatherThanGuessed(t *testing.T) {
	// Zero means "not stated", which the renderer prints as such. Inventing a
	// number would be worse than admitting the parse failed.
	dg := &Digest{Year: 2026, Month: time.May, Sources: []Source{
		{Name: "Qualys", Fetched: true, RawHTML: "<p>nothing useful</p>",
			Text: "nothing useful"},
	}}
	Parse(dg)
	if dg.Total != 0 || dg.Critical != 0 {
		t.Errorf("expected zeroes, got total=%d critical=%d", dg.Total, dg.Critical)
	}
}

func TestDegradedNamesTheSourceAndTheReason(t *testing.T) {
	dg := &Digest{Sources: []Source{
		{Name: "BleepingComputer", Fetched: false, Err: "HTTP 403"},
		{Name: "Qualys", Fetched: true},
	}}
	got := dg.Degraded()
	if len(got) != 1 || !strings.Contains(got[0], "403") {
		t.Errorf("Degraded() = %v", got)
	}
}

func TestFindBleepingArticleMatchesTheMonth(t *testing.T) {
	// The slug carries the flaw count, so it cannot be constructed - only
	// recognised.
	listing := `<a href="https://www.bleepingcomputer.com/news/microsoft/microsoft-august-2026-patch-tuesday-fixes-400-flaws/">Aug</a>
	<a href="https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2026-patch-tuesday-fixes-966-flaws-2-zero-days/">Sep</a>`
	got := FindBleepingArticle(listing, 2026, time.September)
	if !strings.Contains(got, "september-2026") || !strings.Contains(got, "966-flaws") {
		t.Errorf("got %q", got)
	}
	if FindBleepingArticle(listing, 2026, time.October) != "" {
		t.Error("a month with no article should return empty, not a wrong one")
	}
}

// ---------------------------------------------------------------- exposure

func TestSummariseUnionsHostsRatherThanSumming(t *testing.T) {
	// The same machine appears under many QIDs. Summing HostCount across QIDs
	// produces a host count larger than the estate, which is the kind of
	// number that gets a report dismissed.
	cves := []string{"CVE-A", "CVE-B"}
	kb := map[string][]int{"CVE-A": {100, 101}, "CVE-B": {102}}
	det := map[int]DetectionLike{
		100: {QID: 100, HostCount: 2, Hosts: []string{"h1", "h2"}},
		101: {QID: 101, HostCount: 2, Hosts: []string{"h1", "h2"}},
		102: {QID: 102, HostCount: 1, Hosts: []string{"h2"}},
	}
	e := Summarise(cves, kb, det, false)
	if e.Hosts != 2 {
		t.Errorf("Hosts = %d, want 2 distinct (h1, h2)", e.Hosts)
	}
	if e.Detections != 5 {
		t.Errorf("Detections = %d, want 5 (detections DO sum)", e.Detections)
	}
}

func TestSummariseSeparatesUnmappedFromAbsent(t *testing.T) {
	// A CVE with no QID is unmeasurable, not clean. Folding it into "not
	// present" is the failure this whole system is built to avoid.
	e := Summarise([]string{"CVE-MAPPED", "CVE-NOQID"},
		map[string][]int{"CVE-MAPPED": {1}},
		map[int]DetectionLike{1: {QID: 1, HostCount: 1, Hosts: []string{"h"}}}, false)
	if len(e.MappedCVEs) != 1 || e.MappedCVEs[0] != "CVE-MAPPED" {
		t.Errorf("MappedCVEs = %v", e.MappedCVEs)
	}
	if len(e.UnmappedCVEs) != 1 || e.UnmappedCVEs[0] != "CVE-NOQID" {
		t.Errorf("UnmappedCVEs = %v", e.UnmappedCVEs)
	}
}

func TestSummariseOnlyCountsPresentCVEsAsPresent(t *testing.T) {
	e := Summarise([]string{"CVE-HERE", "CVE-CLEAN"},
		map[string][]int{"CVE-HERE": {1}, "CVE-CLEAN": {2}},
		map[int]DetectionLike{
			1: {QID: 1, HostCount: 3, Hosts: []string{"a", "b", "c"}},
			2: {QID: 2, HostCount: 0},
		}, false)
	if len(e.PresentCVEs) != 1 || e.PresentCVEs[0] != "CVE-HERE" {
		t.Errorf("PresentCVEs = %v", e.PresentCVEs)
	}
}

func TestQQLMatchesTheFormatAlreadyInUse(t *testing.T) {
	// Byte-compatible with what has gone out by hand for months. Someone
	// pasting this should not be able to tell a machine wrote it.
	got := QQLForQIDs([]int{110525, 110526, 387304})
	want := "vulnerabilities.vulnerability: ( qid: 110525 or qid: 110526 or qid: 387304 )"
	if got != want {
		t.Errorf("\ngot  %s\nwant %s", got, want)
	}
	if QQLForQIDs(nil) != "" {
		t.Error("no QIDs should produce no query, not an empty parenthesis")
	}
}

func TestDetectedQIDsExcludesQIDsWithNothingFound(t *testing.T) {
	// A query listing QIDs with no detections returns an empty set in the
	// console and looks like the query is broken.
	e := Exposure{QIDs: []int{1, 2, 3}}
	det := map[int]DetectionLike{
		1: {QID: 1, HostCount: 4}, 2: {QID: 2, HostCount: 0},
	}
	got := e.DetectedQIDs(det)
	if len(got) != 1 || got[0] != 1 {
		t.Errorf("DetectedQIDs = %v, want [1]", got)
	}
}

func TestExposureLineDistinguishesUnmeasuredFromClean(t *testing.T) {
	// Three genuinely different states, and the difference matters most on the
	// morning after a release when the KnowledgeBase has not caught up.
	unmeasured := Exposure{}.ExposureLine("CR")
	if !strings.Contains(unmeasured, "not yet measurable") ||
		!strings.Contains(unmeasured, "not a clean result") {
		t.Errorf("unmeasured: %q", unmeasured)
	}

	clean := Exposure{MappedCVEs: []string{"CVE-1"}}.ExposureLine("CR")
	if !strings.Contains(clean, "no open detections") ||
		!strings.Contains(clean, "last scan date") {
		t.Errorf("clean: %q", clean)
	}

	real := Exposure{MappedCVEs: []string{"CVE-1"}, Detections: 1510, Hosts: 777}
	line := real.ExposureLine("CR")
	if !strings.Contains(line, "~1510 new vulnerabilities across 777 hosts") {
		t.Errorf("real: %q", line)
	}
}

// ---------------------------------------------------------------- rendering

func report(t *testing.T) *Report {
	t.Helper()
	r := &Report{Digest: parsed(t), Org: "Construction Resources",
		Exposure: Exposure{
			MappedCVEs: []string{"CVE-2026-1111"}, PresentCVEs: []string{"CVE-2026-1111"},
			UnmappedCVEs: []string{"CVE-2025-9999"},
			QIDs:         []int{110525}, Detections: 1510, Hosts: 777,
		},
		Highlights: []Highlight{{CVE: "CVE-2026-1111", Sev: "Sev5", Hosts: 12,
			QIDs: []int{110525}, KEV: true, EPSS: 0.94, CVSS: 9.8,
			Rationale: "on CISA KEV; PRESENT on 12 host(s)"}},
	}
	r.ChooseQQL([]int{110525})
	return r
}

func TestSubjectMatchesTheEstablishedThread(t *testing.T) {
	r := report(t)
	if !strings.HasPrefix(r.Subject(), "Microsoft Patch Tuesday for May 2026") {
		t.Errorf("subject = %q", r.Subject())
	}
}

func TestQQLPrefersOurOwnDetections(t *testing.T) {
	r := report(t)
	if !strings.Contains(r.QQL, "qid: 110525") {
		t.Errorf("QQL = %q", r.QQL)
	}
	if !strings.Contains(r.QQLSource, "open detections in our environment") {
		t.Errorf("QQLSource = %q", r.QQLSource)
	}
}

func TestQQLFallsBackToTheSourcesThenToCVEs(t *testing.T) {
	r := &Report{Digest: parsed(t), Org: "CR"}
	r.ChooseQQL(nil) // nothing detected here
	if !strings.Contains(r.QQL, "qid: 110525") {
		t.Errorf("should fall back to the published QQL, got %q", r.QQL)
	}
	if !strings.Contains(r.QQLSource, "verbatim") {
		t.Errorf("QQLSource = %q", r.QQLSource)
	}

	bare := &Digest{Year: 2026, Month: time.May, CVEs: []string{"CVE-1", "CVE-2"}}
	r2 := &Report{Digest: bare, Org: "CR"}
	r2.ChooseQQL(nil)
	if !strings.Contains(r2.QQL, "cveIds") {
		t.Errorf("last resort should be a CVE filter, got %q", r2.QQL)
	}
}

func TestHTMLCarriesTheThingsTheReaderCameFor(t *testing.T) {
	h := report(t).HTML()
	for _, want := range []string{
		"Construction Resources",                        // whose it is
		"~1510 new vulnerabilities across 777 hosts",    // the exposure line
		"qid: 110525",                                   // the QQL, pasteable
		"CVE-2026-1111",                                 // present here
		"Sev5",                                          // banded
		"no Qualys QID mapping",                         // the coverage caveat
		"Present in our environment",                    // the section that makes it ours
		"137",                                           // Microsoft's count
		"Spoofing Vulnerability",                        // category table
		"Adobe",                                         // Adobe section
		"determined solely by Qualys Host Detection",    // the standing caveat
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if c := strings.Count(h, "<tr"); c != strings.Count(h, "</tr>") {
		t.Errorf("unbalanced rows: %d open, %d close", c, strings.Count(h, "</tr>"))
	}
	if c := strings.Count(h, "<table"); c != strings.Count(h, "</table>") {
		t.Errorf("unbalanced tables")
	}
}

func TestHTMLEscapesWhatItPullsFromThirdPartySites(t *testing.T) {
	// The narrative fields come from pages we do not control.
	dg := parsed(t)
	dg.AdobeText = `<script>alert(1)</script> and "quotes"`
	r := &Report{Digest: dg, Org: "CR<b>"}
	h := r.HTML()
	if strings.Contains(h, "<script>alert(1)</script>") {
		t.Error("script from a source page survived into the email")
	}
	if strings.Contains(h, "CR<b>") {
		t.Error("org name not escaped")
	}
}

func TestDegradedBannerAppearsAndSaysExposureIsUnaffected(t *testing.T) {
	dg := parsed(t)
	dg.Sources[1].Fetched = false
	dg.Sources[1].Err = "HTTP 403"
	r := &Report{Digest: dg, Org: "CR"}
	h := r.HTML()
	if !strings.Contains(h, "Incomplete sources") || !strings.Contains(h, "403") {
		t.Error("degraded banner missing")
	}
	if !strings.Contains(h, "exposure figures come from Qualys and are unaffected") {
		t.Error("should say which numbers are still trustworthy")
	}
}

func TestTextVersionLeadsWithTheQQLOnItsOwnLine(t *testing.T) {
	// Someone will copy this out of a plain-text client.
	txt := report(t).Text()
	if !strings.Contains(txt, "vulnerabilities.vulnerability: ( qid: 110525 )") {
		t.Errorf("QQL not in the text version:\n%s", txt)
	}
	if !strings.Contains(txt, "coverage unverified") {
		t.Error("text version should carry the unmapped caveat too")
	}
}

func TestNotStatedRatherThanZero(t *testing.T) {
	// A release that fixed zero vulnerabilities has never happened, so
	// printing 0 would read as a successful parse of a quiet month.
	r := &Report{Digest: &Digest{Year: 2026, Month: time.May,
		Sources: []Source{{Name: "Qualys", Fetched: true, Text: "x", RawHTML: "x"}}},
		Org: "CR"}
	if !strings.Contains(r.HTML(), "not stated in the sources") {
		t.Error("a missing count should say so")
	}
	if !strings.Contains(r.Text(), "not stated") {
		t.Error("text version too")
	}
}
