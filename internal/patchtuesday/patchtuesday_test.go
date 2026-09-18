package patchtuesday

import (
	"fmt"
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

// The sentences below are the real August 2026 Qualys review, copied as
// published - including its typography, which is the point.
//
// The previous version of this fixture was hand-written in clean ASCII, and
// every pattern passed against it while two of them could not match the actual
// page at all:
//
//   - "month’s" uses U+2019, so `month'?s` never matched, and the entity map
//     in StripHTML never saw it because it is a character, not an entity.
//   - "421<U+00A0>vulnerabilities" separates the number from the word with a
//     non-breaking space, and Go's \s is ASCII-only, so `([\d,]+)\s+vulnerabilit`
//     did not match either. The total silently fell through to
//     BleepingComputer's different, lower headline count.
//
// Injected rather than typed into the literal so the two characters are
// visible in the source instead of being invisible bytes someone later
// "tidies" away.
var punctuationAsPublished = strings.NewReplacer(
	"{RSQUO}", "\u2019", "{NBSP}", "\u00a0")

var qualysFixture = punctuationAsPublished.Replace(`<html><body>
<p>As attackers continue to exploit unpatched vulnerabilities, timely patching
remains critical for reducing exposure and strengthening enterprise security.</p>
<p>This month{RSQUO}s release addresses <strong>421</strong>{NBSP}vulnerabilities, including <strong>62 </strong>critical
and <strong>357</strong> important-severity<strong> </strong>vulnerabilities.</p>
<p>vulnerabilities.vulnerability: ( qid: 110531 or qid: 110532 or qid: 388257 )</p>
<p>In this month{RSQUO}s updates, Microsoft has addressed <strong>three</strong> zero-day
vulnerabilities: <strong>two</strong> publicly disclosed and <strong>one</strong> exploited in the wild.</p>
<p>Microsoft has addressed 128 vulnerabilities in Microsoft Edge (Chromium-based) that were patched earlier this month.</p>
<p>Microsoft Patch Tuesday, August edition, includes updates for vulnerabilities in Windows HTTP.sys, Windows Hyper-V, .NET, Microsoft Exchange Server, and more.</p>
<p>The August 2026 Microsoft vulnerabilities are classified as follows:</p>
<table><tbody>
<tr><td><b>Vulnerability Category</b></td><td><b>Quantity</b></td><td><b>Severities</b></td></tr>
<tr><td>Spoofing Vulnerability</td><td>20</td><td>Critical: 3<br/>Important: 17</td></tr>
<tr><td>Remote Code Execution Vulnerability</td><td>109</td><td>Critical: 39<br/>Important: 70</td></tr>
</tbody></table>
<p>Adobe has released five security advisories addressing 51 vulnerabilities across Adobe ColdFusion and Adobe Commerce. 33 of these vulnerabilities are rated critical.</p>
<p>Affected: CVE-2026-1111 in Windows Kernel, CVE-2026-2222 in Microsoft Office and CVE-2025-9999 in Windows NTFS.</p>
</body></html>`)

// The headline, then the site's own navigation, then the prose. The nav block
// is here deliberately: with an unbounded [^.] the zero-day pattern ran off
// the end of the headline - which has no full stop of its own - and through
// these list items until it found one, and the August replay published
// "3 zero-days News Featured Latest OpenAI details more cases of AI agents
// taking unauthorized actions ... just $82." as the zero-day summary.
const bleepingFixture = `<html><body>
<h1>Microsoft August 2026 Patch Tuesday fixes 400 flaws, 3 zero-days</h1>
<ul>
<li>News Featured Latest OpenAI details more cases of AI agents taking unauthorized actions</li>
<li>Cisco warns of max severity ISE zero-day exploited in attacks</li>
<li>Need a second laptop? This refurbished Chromebook is just $82.</li>
</ul>
<p>Today is Microsoft's August 2026 Patch Tuesday, which fixes 400 flaws,
including three actively exploited zero-day vulnerabilities.</p>
<p>See CVE-2026-3333 for details.</p>
</body></html>`

func parsed(t *testing.T) *Digest {
	t.Helper()
	dg := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "Qualys security update review", Role: RoleQualysBlog,
			URL: "q", Fetched: true,
			RawHTML: qualysFixture, Text: StripHTML(qualysFixture)},
		{Name: "BleepingComputer Patch Tuesday", Role: RoleBleeping,
			URL: "b", Fetched: true,
			RawHTML: bleepingFixture, Text: StripHTML(bleepingFixture)},
	}}
	Parse(dg)
	return dg
}

func TestParseCounts(t *testing.T) {
	dg := parsed(t)
	// 421, not BleepingComputer's 400: the two publishers count differently
	// and the Qualys post is the primary source. Getting 400 here means the
	// Qualys sentence did not match and the parse fell through.
	if dg.Total != 421 {
		t.Errorf("Total = %d, want 421 (400 means it fell through to BleepingComputer)", dg.Total)
	}
	if dg.Critical != 62 {
		t.Errorf("Critical = %d, want 62", dg.Critical)
	}
	if dg.Important != 357 {
		t.Errorf("Important = %d, want 357", dg.Important)
	}
	if dg.EdgeFixes != 128 {
		t.Errorf("EdgeFixes = %d, want 128", dg.EdgeFixes)
	}
}

func TestParseSurvivesThePublishersTypography(t *testing.T) {
	// Guards the two silent failures directly, because both are invisible in
	// the rendered output: a wrong-but-plausible number, and a missing
	// sentence. Go's \s does not match U+00A0 and 'month'?s' does not match
	// "month’s".
	if !strings.Contains(qualysFixture, "\u00a0") ||
		!strings.Contains(qualysFixture, "\u2019") {
		t.Fatal("fixture no longer contains the published typography it exists to test")
	}
	text := StripHTML(qualysFixture)
	if strings.ContainsAny(text, "\u00a0\u2019") {
		t.Error("StripHTML left smart punctuation in the text it hands to the patterns")
	}
	if !strings.Contains(text, "addresses 421 vulnerabilities") {
		t.Errorf("the non-breaking space was not normalised:\n%.200s", text)
	}
	if !strings.Contains(text, "month's") {
		t.Error("the curly apostrophe was not normalised")
	}
}

func TestStripHTMLMakesOneLinePerBlock(t *testing.T) {
	// The invariant the prose patterns depend on. Bounding a sentence with
	// [^.\n] is only correct if a line is a block; if a merely WRAPPED
	// paragraph stays two lines, the bound cuts sentences in half. That is
	// what happened to the review's zero-day sentence, which wraps in the
	// page source - it went from the vendor's full sentence to empty, and the
	// renderer's response to empty is to omit the section silently.
	got := StripHTML("<p>one sentence that\nwraps across\nthree source lines.</p>" +
		"<p>second block</p><div>third<br>fourth</div>")
	want := "one sentence that wraps across three source lines.\nsecond block\nthird\nfourth"
	if got != want {
		t.Errorf("\ngot  %q\nwant %q", got, want)
	}
	// And on the fixture, where it matters.
	for _, line := range strings.Split(StripHTML(qualysFixture), "\n") {
		if strings.Contains(line, "zero-day") && !strings.HasSuffix(line, ".") {
			t.Errorf("zero-day block is not a whole sentence on one line: %q", line)
		}
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
	if !strings.Contains(dg.ZeroDayText, "exploited in the wild") {
		t.Errorf("expected the blog's full sentence, got %q", dg.ZeroDayText)
	}
}

func TestZeroDayTextDoesNotSwallowSiteNavigation(t *testing.T) {
	// The bug this guards, reproduced exactly: BleepingComputer alone, whose
	// headline has no sentence end. An unbounded [^.] walked out of the
	// headline and into the nav until it found a full stop three stories
	// later. Patterns are line-bounded now, and capped in length.
	dg := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "BleepingComputer Patch Tuesday", Role: RoleBleeping, Fetched: true,
			RawHTML: bleepingFixture, Text: StripHTML(bleepingFixture)},
	}}
	Parse(dg)
	for _, junk := range []string{"OpenAI", "Chromebook", "$82", "Featured Latest"} {
		if strings.Contains(dg.ZeroDayText, junk) {
			t.Errorf("site navigation leaked into the zero-day summary (%q):\n%s",
				junk, dg.ZeroDayText)
		}
	}
	if len(dg.ZeroDayText) > maxProse {
		t.Errorf("zero-day text is %d chars - too long to be one sentence", len(dg.ZeroDayText))
	}
	if !strings.Contains(dg.ZeroDayText, "zero-day") {
		t.Errorf("nothing extracted at all: %q", dg.ZeroDayText)
	}
}

func TestProductListSurvivesProductNamesContainingDots(t *testing.T) {
	// "Windows HTTP.sys" and ".NET" are why [^.]+ cannot terminate this
	// sentence. It used to cut at the dot in ".sys" and publish
	// "Products: Windows HTTP, and more."
	dg := parsed(t)
	got := strings.Join(dg.Products, " | ")
	for _, want := range []string{"Windows HTTP.sys", ".NET", "Microsoft Exchange Server"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from products: %v", want, dg.Products)
		}
	}
	if len(dg.Products) < 4 {
		t.Errorf("expected the whole list, got %v", dg.Products)
	}
	for _, p := range dg.Products {
		if strings.EqualFold(p, "and more") || p == "" {
			t.Errorf("junk entry %q in %v", p, dg.Products)
		}
	}
}

func TestParseRecordsWhereEachFigureCameFrom(t *testing.T) {
	// Provenance exists because a total of 400 looked exactly as plausible as
	// 421 in the rendered email, and nothing said which page it came from.
	dg := parsed(t)
	if got := dg.From["total"]; !strings.Contains(got, "Qualys") {
		t.Errorf("total provenance = %q, want the Qualys review", got)
	}
	if got := dg.From["critical"]; !strings.Contains(got, "Qualys") {
		t.Errorf("critical provenance = %q", got)
	}
	// A figure that was not found says so, rather than being absent from the
	// map and indistinguishable from one nobody looked for.
	bare := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "Qualys security update review", Role: RoleQualysBlog,
			Fetched: true, Text: "nothing useful", RawHTML: "<p>nothing useful</p>"},
	}}
	Parse(bare)
	if bare.From["total"] != "not found in any source" {
		t.Errorf("From[total] = %q", bare.From["total"])
	}
}

func TestTheExposurePlaceholderCannotBeMistakenForTheBlog(t *testing.T) {
	// Roles exist because the source appended after a failed correlation is
	// called "Qualys Host Detection (exposure)", which matched the old
	// name-contains-"qualys" test, has no text, and displaced the real blog.
	dg := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "Qualys security update review", Role: RoleQualysBlog, Fetched: true,
			RawHTML: qualysFixture, Text: StripHTML(qualysFixture)},
		{Name: "Qualys Host Detection (exposure)", Role: RoleExposure,
			Fetched: false, Err: "config: missing QUALYS_PASSWORD"},
	}}
	Parse(dg)
	if dg.Total != 421 {
		t.Errorf("Total = %d - the exposure placeholder displaced the blog", dg.Total)
	}
	if len(dg.Categories) == 0 {
		t.Error("category table lost: the wrong source was treated as the blog")
	}
	// And with no Role set at all, the name heuristic must still exclude it.
	dg2 := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "Qualys security update review", Fetched: true,
			RawHTML: qualysFixture, Text: StripHTML(qualysFixture)},
		{Name: "Qualys Host Detection (exposure)", Fetched: false, Err: "no creds"},
	}}
	Parse(dg2)
	if dg2.Total != 421 {
		t.Errorf("Total = %d with roles unset", dg2.Total)
	}
}

func TestParseQQLIsVerbatim(t *testing.T) {
	// The whole point of exposing it: someone pastes this into Qualys. A
	// paraphrase silently returns the wrong set.
	dg := parsed(t)
	if len(dg.SourceQQL) == 0 {
		t.Fatal("no QQL extracted")
	}
	want := "vulnerabilities.vulnerability: ( qid: 110531 or qid: 110532 or qid: 388257 )"
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

func TestPublishedQIDsComeOutOfTheReviewsOwnQQL(t *testing.T) {
	// The QQL is Qualys stating which detections this release introduced, on
	// the day, in machine-readable form. Reading it back is the difference
	// between measurable exposure on Patch Tuesday + 1 and a report that says
	// "not yet measurable" directly above a list of usable QIDs.
	got := parsed(t).PublishedQIDs()
	want := []int{110531, 110532, 388257}
	if len(got) != len(want) {
		t.Fatalf("PublishedQIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PublishedQIDs = %v, want %v", got, want)
			break
		}
	}
	// Deduped, sorted, case-insensitive, and tolerant of the spacing variants
	// that appear in hand-written queries.
	//
	// The short QIDs are here on purpose. This assertion failed first time
	// against a three-digit floor in the pattern, which had looked like
	// harmless defensiveness: Patch Tuesday QIDs are always five or six
	// digits. But Qualys issues low QIDs too, and a floor drops one out of a
	// published query silently - the exact shape of bug this lane keeps
	// producing. The "qid:" label is what makes a short number trustworthy.
	mixed := QIDsFromQQL([]string{
		"vulnerabilities.vulnerability: ( qid:6 or qid: 6 or QID : 45 )",
		"vulnerabilities.vulnerability: ( qid: 110531 )",
	})
	if len(mixed) != 3 || mixed[0] != 6 || mixed[1] != 45 || mixed[2] != 110531 {
		t.Errorf("QIDsFromQQL = %v, want [6 45 110531]", mixed)
	}
	if len(QIDsFromQQL(nil)) != 0 {
		t.Error("no QQL should yield no QIDs")
	}
	// A number with no label is not a QID, however plausible it looks.
	if got := QIDsFromQQL([]string{"110531 or something: 92437"}); len(got) != 0 {
		t.Errorf("unlabelled numbers should not be read as QIDs: %v", got)
	}
}

func TestParseCategoryTable(t *testing.T) {
	dg := parsed(t)
	if len(dg.Categories) != 2 {
		t.Fatalf("got %d categories: %+v", len(dg.Categories), dg.Categories)
	}
	if dg.Categories[0].Name != "Spoofing Vulnerability" || dg.Categories[0].Quantity != 20 {
		t.Errorf("row 0 = %+v", dg.Categories[0])
	}
	if !strings.Contains(dg.Categories[1].Severities, "Critical: 39") {
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
	e := Summarise(cves, kb, nil, det, false)
	if e.Hosts != 2 {
		t.Errorf("Hosts = %d, want 2 distinct (h1, h2)", e.Hosts)
	}
	if e.Detections != 5 {
		t.Errorf("Detections = %d, want 5 (detections DO sum)", e.Detections)
	}
}

func TestSummariseCountsEachQIDOnceHoweverManyCVEsReachIt(t *testing.T) {
	// Two CVEs sharing a QID is one set of findings on those machines, not
	// two. Summing per (CVE, QID) pair inflated the detection count by
	// however many CVEs happened to map to the same detection.
	e := Summarise([]string{"CVE-A", "CVE-B"},
		map[string][]int{"CVE-A": {100}, "CVE-B": {100}},
		nil,
		map[int]DetectionLike{100: {QID: 100, HostCount: 3, Hosts: []string{"h1", "h2", "h3"}}},
		false)
	if e.Detections != 3 {
		t.Errorf("Detections = %d, want 3 counted once for QID 100", e.Detections)
	}
	if len(e.PresentCVEs) != 2 {
		t.Errorf("both CVEs are still present: %v", e.PresentCVEs)
	}
}

func TestSummariseSeparatesUnmappedFromAbsent(t *testing.T) {
	// A CVE with no QID is unmeasurable, not clean. Folding it into "not
	// present" is the failure this whole system is built to avoid.
	e := Summarise([]string{"CVE-MAPPED", "CVE-NOQID"},
		map[string][]int{"CVE-MAPPED": {1}}, nil,
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
		map[string][]int{"CVE-HERE": {1}, "CVE-CLEAN": {2}}, nil,
		map[int]DetectionLike{
			1: {QID: 1, HostCount: 3, Hosts: []string{"a", "b", "c"}},
			2: {QID: 2, HostCount: 0},
		}, false)
	if len(e.PresentCVEs) != 1 || e.PresentCVEs[0] != "CVE-HERE" {
		t.Errorf("PresentCVEs = %v", e.PresentCVEs)
	}
}

func TestPublishedQIDsMakeExposureMeasurableWithNoCVEMapping(t *testing.T) {
	// The day-one case, and the one the lane got wrong: the KnowledgeBase has
	// no CVE mapping yet, so the CVE route yields nothing - but Qualys
	// published the release's QIDs in the review, and two of them are on our
	// machines. The old code queried neither and reported "not yet
	// measurable" while printing those QIDs in the next paragraph.
	e := Summarise(
		[]string{"CVE-2026-1111", "CVE-2026-2222"},
		map[string][]int{}, // KnowledgeBase has not caught up
		[]int{110531, 110532, 388257},
		map[int]DetectionLike{
			110531: {QID: 110531, HostCount: 40, Hosts: []string{"h1", "h2"}},
			110532: {QID: 110532, HostCount: 2, Hosts: []string{"h2", "h3"}},
			388257: {QID: 388257, HostCount: 0},
		}, true)

	if !e.Measurable() {
		t.Fatal("published QIDs were queried, so this is measurable")
	}
	if e.Detections != 42 || e.Hosts != 3 {
		t.Errorf("Detections = %d (want 42), Hosts = %d (want 3)", e.Detections, e.Hosts)
	}
	if len(e.PublishedOnlyQIDs) != 2 {
		t.Errorf("PublishedOnlyQIDs = %v, want the 2 detecting QIDs no CVE reached",
			e.PublishedOnlyQIDs)
	}
	// Still honest about the CVEs themselves: none of them mapped, so none is
	// claimed as present.
	if len(e.PresentCVEs) != 0 {
		t.Errorf("PresentCVEs = %v - a QID hit does not name a CVE", e.PresentCVEs)
	}
	if len(e.UnmappedCVEs) != 2 {
		t.Errorf("UnmappedCVEs = %v", e.UnmappedCVEs)
	}
	line := e.ExposureLine("CR")
	if strings.Contains(line, "not yet measurable") || strings.Contains(line, "NOT MEASURED") {
		t.Errorf("42 detections is a measurement: %q", line)
	}
	if !strings.Contains(line, "published") {
		t.Errorf("should credit the route that found them: %q", line)
	}
}

func TestHostsAreUnionedNotCappedBySampleSize(t *testing.T) {
	// The August table printed "20 host(s)" for every CVE mapped to two QIDs
	// and "10" for every CVE mapped to one, because the client capped its host
	// NAME list at ten per QID and this package unioned the caps. Every number
	// in the column was the buffer size.
	//
	// Same ten machines under both QIDs: the answer is ten, not twenty.
	same := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10"}
	e := Summarise([]string{"CVE-A"},
		map[string][]int{"CVE-A": {92439, 92440}}, nil,
		map[int]DetectionLike{
			92439: {QID: 92439, HostCount: 10, Hosts: same},
			92440: {QID: 92440, HostCount: 10, Hosts: same},
		}, false)
	if e.Hosts != 10 {
		t.Errorf("Hosts = %d, want 10 distinct machines (20 means samples were summed)", e.Hosts)
	}
	if e.Detections != 20 {
		t.Errorf("Detections = %d, want 20 - detections do sum, machines do not", e.Detections)
	}
	if e.HostsAreFloor {
		t.Error("nothing was truncated, so the count is exact")
	}
}

func TestATruncatedHostListIsReportedAsAFloor(t *testing.T) {
	// When the provider does cut the list off, the union is a lower bound.
	// Printing it as a count is the same lie in a bigger estate.
	e := Summarise([]string{"CVE-A"},
		map[string][]int{"CVE-A": {1}}, nil,
		map[int]DetectionLike{
			1: {QID: 1, HostCount: 4000, Hosts: []string{"h1", "h2"}, HostsTruncated: true},
		}, false)
	if !e.HostsAreFloor {
		t.Error("a truncated host list makes the union a floor")
	}
	line := e.ExposureLine("CR")
	if !strings.Contains(line, "at least") {
		t.Errorf("a floor has to be worded as one: %q", line)
	}
	// And the floor is detected even when the provider forgets the flag.
	e2 := Summarise([]string{"CVE-A"},
		map[string][]int{"CVE-A": {1}}, nil,
		map[int]DetectionLike{1: {QID: 1, HostCount: 900, Hosts: []string{"h1"}}}, false)
	if !e2.HostsAreFloor {
		t.Error("HostCount above len(Hosts) means the list was incomplete")
	}
}

func TestDetectingQIDsAreTheUnitOfWork(t *testing.T) {
	// 353 "present" CVEs was twelve missing patches: Qualys maps every CVE in
	// a monthly cumulative update to one QID. The email has to carry the patch
	// count or a dozen updates read as hundreds of separate findings.
	kb := map[string][]int{}
	var cves []string
	for i := 0; i < 200; i++ {
		c := fmt.Sprintf("CVE-2026-%05d", i)
		cves = append(cves, c)
		kb[c] = []int{92439} // one rollup QID for all of them
	}
	e := Summarise(cves, kb, nil,
		map[int]DetectionLike{92439: {QID: 92439, HostCount: 10,
			Hosts: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}}}, false)
	if len(e.PresentCVEs) != 200 {
		t.Fatalf("PresentCVEs = %d, want 200", len(e.PresentCVEs))
	}
	if len(e.DetectingQIDs) != 1 {
		t.Errorf("DetectingQIDs = %v, want the single rollup QID", e.DetectingQIDs)
	}
	line := e.ExposureLine("CR")
	if !strings.Contains(line, "1 missing Qualys detection") {
		t.Errorf("the patch count belongs in the headline: %q", line)
	}
	if !strings.Contains(line, "200 of this release's CVEs") {
		t.Errorf("and so does the CVE count: %q", line)
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
	// Four genuinely different states. The difference matters most on the
	// morning after a release, when the KnowledgeBase has not caught up and
	// the reader is deciding whether to act before breakfast.
	notMeasured := Unmeasured("config: missing QUALYS_PASSWORD").ExposureLine("CR")
	if !strings.Contains(notMeasured, "NOT MEASURED") ||
		!strings.Contains(notMeasured, "QUALYS_PASSWORD") ||
		!strings.Contains(notMeasured, "not a clean result") {
		t.Errorf("not measured: %q", notMeasured)
	}

	noQIDs := Exposure{Attempted: true}.ExposureLine("CR")
	if !strings.Contains(noQIDs, "not yet measurable") ||
		!strings.Contains(noQIDs, "not a clean result") {
		t.Errorf("no QIDs: %q", noQIDs)
	}

	clean := Exposure{Attempted: true, MappedCVEs: []string{"CVE-1"},
		QIDs: []int{1, 2}}.ExposureLine("CR")
	if !strings.Contains(clean, "no open detections") ||
		!strings.Contains(clean, "last scan date") {
		t.Errorf("clean: %q", clean)
	}

	real := Exposure{Attempted: true, MappedCVEs: []string{"CVE-1"},
		QIDs: []int{1}, Detections: 1510, Hosts: 777}
	if line := real.ExposureLine("CR"); !strings.Contains(line,
		"~1510 new vulnerabilities across 777 hosts") {
		t.Errorf("real: %q", line)
	}
}

func TestAFailedCorrelationNeverDiagnosesTheKnowledgeBase(t *testing.T) {
	// The report he caught. A zero-value Exposure - which is what a failed
	// correlation left behind - printed "the Qualys KnowledgeBase has no QID
	// mapping for any CVE in this release", a confident finding about a
	// system that was never contacted, sitting above a QQL full of QIDs.
	//
	// The rule: nothing may be said about the KnowledgeBase, the scanner or
	// the estate unless the scanner was actually queried.
	for _, e := range []Exposure{
		{},                                  // never populated at all
		Unmeasured("no Qualys credentials"), // populated honestly
	} {
		line := e.ExposureLine("CR")
		for _, forbidden := range []string{
			"KnowledgeBase", "no open detections", "not affected", "clean estate",
		} {
			if strings.Contains(line, forbidden) {
				t.Errorf("an unattempted correlation claimed %q:\n%s", forbidden, line)
			}
		}
		if !strings.Contains(line, "NOT MEASURED") {
			t.Errorf("should say plainly that it did not look: %q", line)
		}
		if e.Measurable() {
			t.Error("an unattempted correlation is not measurable")
		}
		if note := e.CoverageNote(); note != "" {
			t.Errorf("no coverage claim either way without a query: %q", note)
		}
	}
}

func TestCoverageNoteCreditsThePublishedQIDsItQueried(t *testing.T) {
	e := Exposure{Attempted: true, UnmappedCVEs: []string{"CVE-1", "CVE-2"},
		PublishedQIDs: []int{110531}, QIDs: []int{110531}}
	note := e.CoverageNote()
	if !strings.Contains(note, "not the same as not being present") {
		t.Errorf("note = %q", note)
	}
	if !strings.Contains(note, "published") {
		t.Errorf("unmapped CVEs may still be covered by the published QIDs: %q", note)
	}
	if !strings.Contains(Exposure{Attempted: true, UnmappedCVEs: []string{"CVE-1"},
		KBStale: true}.CoverageNote(), "stale") {
		t.Error("a stale cache has to be said out loud")
	}
}

// ---------------------------------------------------------------- rendering

func report(t *testing.T) *Report {
	t.Helper()
	r := &Report{Digest: parsed(t), Org: "Construction Resources",
		Exposure: Exposure{
			Attempted:  true,
			MappedCVEs: []string{"CVE-2026-1111"}, PresentCVEs: []string{"CVE-2026-1111"},
			UnmappedCVEs: []string{"CVE-2025-9999"},
			QIDs:         []int{110531}, Detections: 1510, Hosts: 777,
		},
		Highlights: []Highlight{{CVE: "CVE-2026-1111", Sev: "Sev5", Hosts: 12,
			QIDs: []int{110531}, KEV: true, EPSS: 0.94, CVSS: 9.8,
			Rationale: "on CISA KEV; PRESENT on 12 host(s)"}},
	}
	r.ChooseQQL([]int{110531})
	return r
}

func TestSubjectMatchesTheEstablishedThread(t *testing.T) {
	r := report(t)
	if !strings.HasPrefix(r.Subject(), "Microsoft Patch Tuesday for August 2026") {
		t.Errorf("subject = %q", r.Subject())
	}
}

func TestQQLPrefersOurOwnDetections(t *testing.T) {
	r := report(t)
	if !strings.Contains(r.QQL, "qid: 110531") {
		t.Errorf("QQL = %q", r.QQL)
	}
	if !strings.Contains(r.QQLSource, "open detections in our environment") {
		t.Errorf("QQLSource = %q", r.QQLSource)
	}
}

func TestQQLFallsBackToTheSourcesThenToCVEs(t *testing.T) {
	r := &Report{Digest: parsed(t), Org: "CR"}
	r.ChooseQQL(nil) // nothing detected here
	if !strings.Contains(r.QQL, "qid: 110531") {
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
		"Construction Resources",                     // whose it is
		"~1510 new vulnerabilities across 777 hosts", // the exposure line
		"qid: 110531",                                // the QQL, pasteable
		"CVE-2026-1111",                              // present here
		"Sev5",                                       // banded
		"no Qualys QID mapping",                      // the coverage caveat
		"Present in our environment",                 // the section that makes it ours
		"421",                                        // Microsoft's count, per Qualys
		"Windows HTTP.sys",                           // the product list, dots intact
		"Spoofing Vulnerability",                     // category table
		"Adobe",                                      // Adobe section
		"determined solely by Qualys Host Detection", // the standing caveat
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
	r := &Report{Digest: dg, Org: "CR", Exposure: Exposure{Attempted: true,
		QIDs: []int{1}, Detections: 5, Hosts: 2}}
	h := r.HTML()
	if !strings.Contains(h, "Incomplete sources") || !strings.Contains(h, "403") {
		t.Error("degraded banner missing")
	}
	if !strings.Contains(h, "unaffected") {
		t.Error("should say which numbers are still trustworthy")
	}
}

func TestDegradedBannerDoesNotVouchForExposureItNeverGot(t *testing.T) {
	// The banner used to say "the exposure figures come from Qualys and are
	// unaffected" in the same breath as listing the Qualys exposure query
	// among the things that failed.
	dg := parsed(t)
	dg.Sources[1].Fetched = false
	dg.Sources[1].Err = "HTTP 403"
	r := &Report{Digest: dg, Org: "CR", Exposure: Unmeasured("no credentials")}
	h := r.HTML()
	if strings.Contains(h, "unaffected") {
		t.Error("claimed the exposure figures survived when there are none")
	}
	if !strings.Contains(h, "NOT MEASURED") {
		t.Error("the exposure line still has to say it did not look")
	}
}

func TestTextVersionLeadsWithTheQQLOnItsOwnLine(t *testing.T) {
	// Someone will copy this out of a plain-text client.
	txt := report(t).Text()
	if !strings.Contains(txt, "vulnerabilities.vulnerability: ( qid: 110531 )") {
		t.Errorf("QQL not in the text version:\n%s", txt)
	}
	if !strings.Contains(txt, "not the same as not being present") {
		t.Error("text version should carry the unmapped caveat too")
	}
}

func TestTheSeverityColumnIsOmittedRatherThanFilledWithQuestionMarks(t *testing.T) {
	// The August replay printed "?" in every row of the Sev column, because
	// nothing in the lane ever set it. A column that cannot hold a value is
	// not a column.
	r := &Report{Digest: parsed(t), Org: "CR",
		Exposure: Exposure{Attempted: true, QIDs: []int{1}, Detections: 5, Hosts: 2},
		Highlights: []Highlight{
			{CVE: "CVE-2026-1111", Hosts: 9, QIDs: []int{1}},
			{CVE: "CVE-2026-2222", Hosts: 3, QIDs: []int{1}},
		}}
	txt := r.Text()
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "CVE-") &&
			strings.Contains(line, "?") {
			t.Errorf("placeholder severity still printed on a CVE row: %q", line)
		}
	}
	if !strings.Contains(txt, "No severity band") {
		t.Error("the absence should be explained once, not implied per row")
	}
	if strings.Contains(r.HTML(), ">Sev<") {
		t.Error("HTML should drop the Sev header when nothing populates it")
	}

	// With enrichment, the column appears and carries the band.
	r.Highlights[0].Sev = "Sev5"
	r.Highlights[0].Rationale = "on CISA KEV; PRESENT on 9 host(s)"
	txt = r.Text()
	if !strings.Contains(txt, "Sev5") {
		t.Errorf("band missing from the text version:\n%s", txt)
	}
	if !strings.Contains(r.HTML(), ">Sev<") {
		t.Error("HTML should show the Sev header once a band exists")
	}
}

func TestTheTableIsSortedByBlastRadiusAndCapped(t *testing.T) {
	dg := parsed(t)
	// Distinct QID per CVE, so nothing collapses and the cap is what bites.
	var hs []Highlight
	for i := 0; i < 40; i++ {
		hs = append(hs, Highlight{CVE: fmt.Sprintf("CVE-2026-%05d", i),
			Hosts: i, QIDs: []int{1000 + i}})
	}
	r := &Report{Digest: dg, Org: "CR", MaxRows: 5,
		Exposure: Exposure{Attempted: true, QIDs: []int{1}, DetectingQIDs: []int{1},
			Detections: 40, Hosts: 39},
		Highlights: hs}
	shown, hidden := r.rows()
	if len(shown) != 5 || hidden != 35 {
		t.Fatalf("rows() = %d shown, %d hidden; want 5 and 35", len(shown), hidden)
	}
	if shown[0].Hosts != 39 {
		t.Errorf("worst first: got %d hosts at the top", shown[0].Hosts)
	}
	txt := r.Text()
	if !strings.Contains(txt, "and 35 more") {
		t.Errorf("truncation must be stated, not silent:\n%s", txt)
	}
	if !strings.Contains(txt, "(40)") {
		t.Error("the full count still has to appear")
	}
	// An unenriched row must never outrank a known Sev5 at equal host counts.
	tie := &Report{Digest: dg, Org: "CR", Highlights: []Highlight{
		{CVE: "CVE-2026-00001", Hosts: 5, QIDs: []int{1}},
		{CVE: "CVE-2026-00002", Hosts: 5, QIDs: []int{2}, Sev: "Sev5"},
	}}
	if got, _ := tie.rows(); got[0].CVE != "CVE-2026-00002" {
		t.Errorf("Sev5 should break the tie, got %s first", got[0].CVE)
	}
}

func TestOneRowPerUpdateNotOneRowPerCVE(t *testing.T) {
	// The August replay's capped table was 24 CVEs carrying the identical QID
	// pair on the identical 331 hosts, then one other. It stated one fact 24
	// times and pushed the remaining eleven patches below the cut - a cap
	// without collapsing just moves the noise around.
	var hs []Highlight
	for i := 0; i < 200; i++ {
		hs = append(hs, Highlight{CVE: fmt.Sprintf("CVE-2026-%05d", i),
			Hosts: 331, QIDs: []int{92439, 92440}})
	}
	hs = append(hs,
		Highlight{CVE: "CVE-2026-70000", Hosts: 12, QIDs: []int{110532}},
		Highlight{CVE: "CVE-2026-70001", Hosts: 2, QIDs: []int{388257}})

	r := &Report{Digest: parsed(t), Org: "CR", MaxRows: 25,
		Exposure: Exposure{Attempted: true, QIDs: []int{92439, 92440, 110532, 388257},
			DetectingQIDs: []int{92439, 92440, 110532, 388257},
			Detections:    600, Hosts: 340},
		Highlights: hs}

	shown, hidden := r.rows()
	if len(shown) != 3 {
		t.Fatalf("got %d rows, want 3 - one per distinct QID set", len(shown))
	}
	if hidden != 0 {
		t.Errorf("nothing should be hidden: 3 rows is under the cap, got hidden=%d", hidden)
	}
	if shown[0].SharedWith != 199 {
		t.Errorf("the rollup row should account for 199 others, got %d", shown[0].SharedWith)
	}
	// Order is still worst-first, and the small patches survive rather than
	// being pushed under the cut by the big one.
	if shown[1].CVE != "CVE-2026-70000" || shown[2].CVE != "CVE-2026-70001" {
		t.Errorf("smaller updates lost their place: %s, %s", shown[1].CVE, shown[2].CVE)
	}
	txt := r.Text()
	if !strings.Contains(txt, "+199 more CVE(s) fixed by the same update") {
		t.Errorf("the collapse has to be stated:\n%s", txt)
	}
	if !strings.Contains(txt, "(202)") {
		t.Errorf("the true CVE count still has to appear:\n%s", txt)
	}
	if !strings.Contains(txt, "in 3 update(s)") {
		t.Errorf("the heading should say how many updates:\n%s", txt)
	}
}

func TestABandedCVEIsNeverCollapsedBehindAnUnbandedOne(t *testing.T) {
	// An actively exploited CVE has to stay visible even when it shares an
	// update with two hundred others.
	hs := []Highlight{
		{CVE: "CVE-2026-00001", Hosts: 50, QIDs: []int{92439}},
		{CVE: "CVE-2026-00002", Hosts: 50, QIDs: []int{92439}, Sev: "Sev5",
			KEV: true, Rationale: "on CISA KEV"},
		{CVE: "CVE-2026-00003", Hosts: 50, QIDs: []int{92439}},
	}
	r := &Report{Digest: parsed(t), Org: "CR", Highlights: hs}
	shown, _ := r.rows()
	if len(shown) != 1 {
		t.Fatalf("one QID set, want one row, got %d", len(shown))
	}
	if shown[0].CVE != "CVE-2026-00002" || shown[0].Sev != "Sev5" {
		t.Errorf("the banded CVE should represent the group, got %s (%q)",
			shown[0].CVE, shown[0].Sev)
	}
	if shown[0].SharedWith != 2 {
		t.Errorf("SharedWith = %d, want 2", shown[0].SharedWith)
	}
}

func TestACorrelatedCVECanNameTheSentenceThatPutItThere(t *testing.T) {
	// CVE-2026-6726 sorted to the top of the August table on 346 hosts and
	// there was no way to ask which sentence had claimed it belonged to this
	// release. Same class of problem as a total of 400 with no named source.
	dg := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "Qualys security update review", Role: RoleQualysBlog, Fetched: true,
			RawHTML: "x", Text: "Microsoft Patch Tuesday fixes CVE-2026-1111 in Windows NTFS.\n" +
				"Related reading: a Chrome zero-day, CVE-2026-6726, was fixed last week."},
	}}
	Parse(dg)

	got := dg.Explain("CVE-2026-1111")
	if !strings.Contains(got, "Windows NTFS") {
		t.Errorf("should quote the sentence it was found in:\n%s", got)
	}
	if strings.Contains(got, "UNATTRIBUTED") {
		t.Errorf("this one has Microsoft context:\n%s", got)
	}

	// The suspicious one is kept - dropping a real CVE is worse - but named.
	got = dg.Explain("CVE-2026-6726")
	if !strings.Contains(got, "Chrome zero-day") {
		t.Errorf("should quote the context:\n%s", got)
	}
	if !strings.Contains(got, "UNATTRIBUTED") {
		t.Errorf("no Microsoft product context, so say so:\n%s", got)
	}
	if len(dg.UnattributedCVEs) != 1 || dg.UnattributedCVEs[0] != "CVE-2026-6726" {
		t.Errorf("UnattributedCVEs = %v", dg.UnattributedCVEs)
	}
	// Still correlated: presence is a fact about our estate either way.
	if !strings.Contains(strings.Join(dg.CVEs, " "), "CVE-2026-6726") {
		t.Error("an unattributed CVE is flagged, not dropped")
	}

	if !strings.Contains(dg.Explain("CVE-2026-9999"), "does not appear") {
		t.Error("a CVE that was never seen should say exactly that")
	}
}

func TestAdobeOnlyCVEsAreNotCorrelatedAsPartOfTheRelease(t *testing.T) {
	// The scrape found 422 CVE IDs against a stated 421, because it takes
	// every CVE-shaped string off two entire pages - Adobe's advisories
	// included. "This release's CVEs" has to mean Microsoft's release.
	dg := parsed(t)
	joined := strings.Join(dg.CVEs, " ")
	// CVE-2025-9999 sits in a Microsoft "Affected:" line in the fixture and
	// must survive; nothing in the fixture is Adobe-only, so nothing is cut.
	if !strings.Contains(joined, "CVE-2025-9999") {
		t.Errorf("a Microsoft-context CVE was dropped: %v", dg.CVEs)
	}

	scoped := &Digest{Year: 2026, Month: time.August, Sources: []Source{
		{Name: "Qualys security update review", Role: RoleQualysBlog, Fetched: true,
			RawHTML: "x", Text: "Microsoft Patch Tuesday fixes CVE-2026-1111 in Windows.\n" +
				"Adobe has released advisories for CVE-2026-9001 and CVE-2026-9002.\n" +
				"Microsoft Exchange Server is affected by CVE-2026-9002 as well."},
	}}
	Parse(scoped)
	got := strings.Join(scoped.CVEs, " ")
	if !strings.Contains(got, "CVE-2026-1111") {
		t.Errorf("Microsoft CVE dropped: %v", scoped.CVEs)
	}
	if strings.Contains(got, "CVE-2026-9001") {
		t.Errorf("Adobe-only CVE was correlated: %v", scoped.CVEs)
	}
	// Seen in an Adobe line AND a Microsoft line: benefit of the doubt, keep
	// it. Dropping a real CVE is a silent false negative; keeping a spare one
	// only widens a scanner query.
	if !strings.Contains(got, "CVE-2026-9002") {
		t.Errorf("a CVE with Microsoft context was excluded on the Adobe sighting: %v",
			scoped.CVEs)
	}
	if len(scoped.ExcludedCVEs) != 1 || scoped.ExcludedCVEs[0] != "CVE-2026-9001" {
		t.Errorf("exclusions must be recorded for audit, got %v", scoped.ExcludedCVEs)
	}
}

func TestACountMismatchWithThePublisherIsStatedNotHidden(t *testing.T) {
	// The only independent check available on a scrape is the publisher's own
	// total. 422 against 421 is small, and a small unexplained wrongness is
	// what costs a report its credibility.
	d := &Digest{Total: 421, CVEs: make([]string, 422)}
	note := d.CVECountNote()
	if !strings.Contains(note, "422") || !strings.Contains(note, "421") ||
		!strings.Contains(note, "1 more than") {
		t.Errorf("note = %q", note)
	}
	d2 := &Digest{Total: 421, CVEs: make([]string, 400)}
	if !strings.Contains(d2.CVECountNote(), "fewer than") {
		t.Errorf("note = %q", d2.CVECountNote())
	}
	if (&Digest{Total: 421, CVEs: make([]string, 421)}).CVECountNote() != "" {
		t.Error("agreement needs no note")
	}
	if (&Digest{Total: 0, CVEs: make([]string, 5)}).CVECountNote() != "" {
		t.Error("no stated total means nothing to compare against")
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
