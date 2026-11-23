package brief

// The brief.py unit tests from fleet-kit/tests/test_lanes.py, ported test for
// test: same names (CamelCase), same substrings, same counts. Tests that run
// a shell runner, read email-tokens.json or call main() stay in Python.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

// namedNow stands in for Python's datetime.now().
var namedNow = time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC)

// plainEnv is FLEET_ORG, FLEET_ATTRIBUTION and FLEET_REPO_URL all unset.
var plainEnv = Env{Org: "Security"}

// decode is json.loads with numbers kept as json.Number, as the renderer
// expects.
func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("bad test JSON: %v\n%s", err, s)
	}
	return v
}

func decodeObj(t *testing.T, s string) obj {
	t.Helper()
	o, ok := decode(t, s).(obj)
	if !ok {
		t.Fatalf("not a JSON object: %s", s)
	}
	return o
}

func render(d obj, kind string) string { return Render(d, kind, namedNow, plainEnv) }

func renderText(d obj, kind string) string { return RenderText(d, kind, namedNow, plainEnv) }

func subject(d obj, kind string) string { return Subject(d, kind, namedNow) }

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustContain(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Errorf("missing %q in:\n%s", want, body)
	}
}

func mustNotContain(t *testing.T, body, unwanted string) {
	t.Helper()
	if strings.Contains(body, unwanted) {
		t.Errorf("unexpected %q in:\n%s", unwanted, body)
	}
}

// loadTickets is brief.load_tickets: the "tickets" of the map beside the
// enriched file, as Prepare reads it.
func loadTickets(enriched string) obj {
	d := obj{}
	Prepare(d, enriched, "daily", false, namedNow)
	return asObj(d["_tickets"])
}

// ---------------------------------------------------------------- Degradation

// A digest that hides its own gaps is worse than no digest.
func TestDegradedBannerReachesTheDigest(t *testing.T) {
	d := decodeObj(t, `{"generated": "2026-09-02T00:00:00+00:00", "source_meta": {},
		"counts": {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 0}, "total": 0,
		"degraded": ["NVD", "EPSS"], "findings": []}`)
	html := render(d, "daily")
	mustContain(t, html, "DEGRADED")
	mustContain(t, html, "NVD")
}

// ------------------------------------------------------------- BriefRendering

// enriched is an enriched file as cti-enrich writes it: eleven findings
// across every band.
func enriched(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile("../../fleet-kit/tests/testdata/enriched-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var d obj
	if err := dec.Decode(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func findingsOf(d obj) []obj {
	var out []obj
	for _, f := range asList(d["findings"]) {
		out = append(out, asObj(f))
	}
	return out
}

func copyObj(o obj) obj {
	c := obj{}
	for k, v := range o {
		c[k] = v
	}
	return c
}

// A Sev5 leads the subject.
func TestSubjectLeadsWithSev5(t *testing.T) {
	if s := subject(enriched(t), "daily"); !strings.HasPrefix(s, "[Sev5]") {
		t.Errorf("subject %q does not lead with [Sev5]", s)
	}
}

// Without a Sev5 the subject does not claim one.
func TestSubjectWithoutSev5DoesNotCryWolf(t *testing.T) {
	d := enriched(t)
	var kept []any
	for _, f := range findingsOf(d) {
		if str(f["priority"]) != "Sev5" {
			kept = append(kept, f)
		}
	}
	d["findings"] = kept
	asObj(d["counts"])["Sev5"] = json.Number("0")
	if s := subject(d, "daily"); strings.HasPrefix(s, "[Sev5]") {
		t.Errorf("subject %q leads with [Sev5]", s)
	}
}

// An empty run still says something useful.
func TestEmptyRunStillSaysSomethingUseful(t *testing.T) {
	d := decodeObj(t, `{"generated": "x", "source_meta": {}, "total": 0, "degraded": [],
		"counts": {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 0}, "findings": []}`)
	mustContain(t, subject(d, "daily"), "no new CVEs")
	mustContain(t, render(d, "daily"), "Nothing to action")
}

// Table and row tags balance.
func TestHtmlTagsBalance(t *testing.T) {
	html := render(enriched(t), "daily")
	if a, b := strings.Count(html, "<table"), strings.Count(html, "</table>"); a != b {
		t.Errorf("<table %d vs </table> %d", a, b)
	}
	if a, b := strings.Count(html, "<tr"), strings.Count(html, "</tr>"); a != b {
		t.Errorf("<tr %d vs </tr> %d", a, b)
	}
}

// A CVE the team mailed in gets its own section whatever its band, listed once.
func TestACveTheTeamAskedAboutIsListedWhateverItsBand(t *testing.T) {
	d := decodeObj(t, `{"generated": "x", "source_meta": {}, "total": 3, "degraded": [],
		"counts": {"Sev5": 0, "Sev4": 1, "Sev3": 0, "Sev2": 0, "Sev1": 2},
		"findings": [
		 {"cve": "CVE-2026-4004", "priority": "Sev4", "status": "PRESENT", "host_count": 2, "rationale": "r", "asked": true},
		 {"cve": "CVE-2026-123158", "priority": "Sev1", "status": "UNKNOWN", "host_count": 0, "rationale": "r", "asked": true},
		 {"cve": "CVE-2026-1111", "priority": "Sev1", "status": "NOT_PRESENT", "host_count": 0, "rationale": "r", "asked": false}]}`)
	for _, kind := range []string{"daily", "weekly"} {
		html := render(d, kind)
		text := renderText(d, kind)
		for i, body := range []string{html, text} {
			mustContain(t, body, "Asked about")
			mustContain(t, body, "CVE-2026-123158")
			if strings.Contains(body, "CVE-2026-1111") {
				t.Errorf("%s: a Sev1 nobody asked about got a row", kind)
			}
			needle := "CVE-2026-4004</a>"
			if i == 1 {
				needle = "CVE-2026-4004  "
			}
			if n := strings.Count(body, needle); n != 1 {
				t.Errorf("%s: an asked row is listed %d times", kind, n)
			}
			mustContain(t, body, "listed under Asked about")
		}
		if !strings.Contains(html, ">Sev1</span>") {
			t.Errorf("%s: the asked row does not show its band", kind)
		}
		mustContain(t, text, "CVE-2026-123158  Sev1")
		if a, b := strings.Count(html, "<tr"), strings.Count(html, "</tr>"); a != b {
			t.Errorf("%s: <tr %d vs </tr> %d", kind, a, b)
		}
	}
	for _, f := range findingsOf(d) {
		f["asked"] = false
	}
	mustNotContain(t, render(d, "daily"), "Asked about")
	mustNotContain(t, renderText(d, "daily"), "Asked about")
}

// Sev1 is a count, not a list, in either digest.
func TestSev1IsACountNotAListInEitherDigest(t *testing.T) {
	d := enriched(t)
	sev1 := regexp.MustCompile(`Sev1 \d+`)
	for _, kind := range []string{"daily", "weekly"} {
		html := render(d, kind)
		if strings.Contains(html, "Awareness only") {
			t.Errorf("%s: Sev1 should have no section", kind)
		}
		if !strings.Contains(html, ">Sev1<") {
			t.Errorf("%s: the Sev1 count tile is missing", kind)
		}
		text := renderText(d, kind)
		var strip []string
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, "Sev5") && strings.Contains(l, "Sev1") && strings.Contains(l, "total") {
				strip = append(strip, l)
			}
		}
		if len(strip) != 1 {
			t.Fatalf("%s: expected exactly one counts strip, got %q", kind, strip)
		}
		if !sev1.MatchString(strip[0]) {
			t.Errorf("%s: the strip should carry a Sev1 number: %q", kind, strip[0])
		}
		if strings.Contains(text, "Sev1 - Awareness only") {
			t.Errorf("%s: Sev1 should have no text section", kind)
		}
	}
}

// The text renderer caps rows from the same table as the HTML.
func TestBothRenderersCapTheSameWay(t *testing.T) {
	d := enriched(t)
	for _, kind := range []string{"daily", "weekly"} {
		text := renderText(d, kind)
		for band, limit := range RowLimits[kind] {
			var group []obj
			for _, f := range findingsOf(d) {
				if str(f["priority"]) == band {
					group = append(group, f)
				}
			}
			shown := 0
			for _, line := range strings.Split(text, "\n") {
				if !strings.HasPrefix(line, "  CVE-") {
					continue
				}
				for _, f := range group {
					if strings.Contains(line, str(f["cve"])) {
						shown++
						break
					}
				}
			}
			if shown > limit {
				t.Errorf("%s/%s: %d rows exceeds the cap of %d", kind, band, shown, limit)
			}
		}
	}
}

// A truncated list says so in the text version too.
func TestTruncationIsStatedInTheTextVersionToo(t *testing.T) {
	d := enriched(t)
	limit := RowLimits["daily"]["Sev4"]
	first := findingsOf(d)[0]
	var rows []any
	for i := 0; i < limit+3; i++ {
		f := copyObj(first)
		f["cve"] = "CVE-2026-" + itoa(9000+i)
		f["priority"] = "Sev4"
		f["status"] = "PRESENT"
		f["host_count"] = json.Number("5")
		rows = append(rows, f)
	}
	d["findings"] = rows
	d["counts"] = obj{"Sev5": json0, "Sev4": json.Number(itoa(limit + 3)), "Sev3": json0, "Sev2": json0, "Sev1": json0}
	text := renderText(d, "daily")
	if !strings.Contains(text, "+3 more Sev4 in the full report") {
		t.Errorf("a list that silently stops is one the reader believes is complete:\n%s", text)
	}
}

// Duplicate sample hostnames collapse.
func TestSampleHostsAreDeduped(t *testing.T) {
	html := render(enriched(t), "daily")
	// CVE-2026-45659's sample hosts are "h6, h6" in the fixture.
	if n := strings.Count(html, ">h6<") + strings.Count(html, " h6,"); n != 0 {
		t.Errorf("duplicate hostnames should collapse (%d)", n)
	}
}

// No address is invented when the source metadata is missing.
func TestNoHardcodedAddressWhenMetadataMissing(t *testing.T) {
	d := enriched(t)
	d["source_meta"] = obj{}
	head := strings.Split(render(d, "daily"), "Generated by")[0]
	parts := strings.Split(head, "Presence is determined")
	mustNotContain(t, parts[len(parts)-1], "@")
}

// The text version renders.
func TestTextVersionRenders(t *testing.T) {
	text := renderText(enriched(t), "daily")
	mustContain(t, text, "Sev5")
	mustContain(t, text, "Presence determined solely")
}

// ---------------------------------------------------------------- Attribution

func attributionData(t *testing.T) obj {
	return decodeObj(t, `{"generated": "2026-09-21T06:00:00Z", "total": 1,
		"counts": {"Sev5": 0, "Sev4": 0, "Sev3": 0, "Sev2": 0, "Sev1": 1},
		"findings": [{"cve": "CVE-2026-1", "priority": "Sev1",
		              "status": "UNKNOWN", "host_count": 0,
		              "cvss": 0, "epss": 0, "kev": 0, "qids": "",
		              "sample_hosts": "", "rationale": "awareness"}],
		"source_meta": {}}`)
}

// Unset keeps the footer it always had and advertises nobody.
func TestUnsetKeepsTheFooterItAlwaysHad(t *testing.T) {
	if text, url := plainEnv.attribution(); text != "" || url != "" {
		t.Errorf("attribution() = (%q, %q), want empty", text, url)
	}
	html := render(attributionData(t), "daily")
	mustContain(t, html, "Generated by the ")
	mustNotContain(t, html, "CTI agent fleet")
	mustNotContain(t, html, "Claude Code Agent Fleet")
}

// A URL alone is enough, and the default text names the org.
func TestAUrlAloneIsEnoughAndNamesTheOrg(t *testing.T) {
	e := Env{Org: "Example Org", RepoURL: "https://github.com/example/cti-agent"}
	text, url := e.attribution()
	mustContain(t, text, "Example Org Claude Code Agent Fleet")
	if url != "https://github.com/example/cti-agent" {
		t.Errorf("url = %q", url)
	}
}

// Explicit text wins and reaches both renderings.
func TestExplicitTextWinsAndReachesBothRenderings(t *testing.T) {
	e := Env{Org: "Security",
		Attribution: "Correlated and published by the CR Claude Code Agent Fleet",
		RepoURL:     "https://github.com/example/cti-agent"}
	html := Render(attributionData(t), "daily", namedNow, e)
	mustContain(t, html, `href="https://github.com/example/cti-agent"`)
	mustContain(t, html, "CR Claude Code Agent Fleet")
	text := RenderText(attributionData(t), "daily", namedNow, e)
	mustContain(t, text, "Correlated and published by the CR Claude Code Agent Fleet")
	// URL on its own line: a text-only reader cannot follow an anchor.
	mustContain(t, text, "\nhttps://github.com/example/cti-agent")
}

// Only http and https links reach the email.
func TestOnlyHttpLinksReachTheEmail(t *testing.T) {
	for _, bad := range []string{"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"file:///etc/passwd",
		"github.com/example/cti-agent",
		"https://",
		"   "} {
		if got := safeLinkURL(bad); got != "" {
			t.Errorf("%q should be refused, got %q", bad, got)
		}
	}
	for _, good := range []string{"https://github.com/example/cti-agent",
		"http://intranet.example.com/cti",
		"HTTPS://GitHub.com/Example/cti-agent"} {
		if safeLinkURL(good) == "" {
			t.Errorf("%q is a usable link", good)
		}
	}
}

// A refused URL does not take the credit text with it.
func TestARefusedUrlDoesNotTakeTheTextWithIt(t *testing.T) {
	e := Env{Org: "Security", Attribution: "Published by the CR fleet",
		RepoURL: "javascript:alert(1)", Warn: func(string) {}}
	text, url := e.attribution()
	if url != "" {
		t.Errorf("url = %q, want empty", url)
	}
	if text != "Published by the CR fleet" {
		t.Errorf("text = %q", text)
	}
	html := Render(attributionData(t), "daily", namedNow, e)
	mustNotContain(t, html, "javascript")
	mustContain(t, html, "Published by the CR fleet")
}

// The credit and its URL are escaped.
func TestTheCreditIsEscaped(t *testing.T) {
	e := Env{Org: "Security", Attribution: "CR <script>alert(1)</script> & co",
		RepoURL: `https://example.com/?a=1&b="2"`}
	html := Render(attributionData(t), "daily", namedNow, e)
	mustNotContain(t, html, "<script>alert(1)</script>")
	mustContain(t, html, "&amp;")
	mustNotContain(t, html, `b="2"`)
}

// --------------------------------------------------- BandLabelsDoNotOverclaim

func bandData(findings []any, counts map[string]int) obj {
	c := obj{"Sev5": json0, "Sev4": json0, "Sev3": json0, "Sev2": json0, "Sev1": json0}
	for k, v := range counts {
		c[k] = json.Number(itoa(v))
	}
	return obj{"counts": c, "total": json.Number(itoa(len(findings))), "degraded": []any{},
		"source_meta": obj{}, "generated": "g", "kev_deadlines": obj{},
		"findings": findings}
}

func unknownRow(t *testing.T, cve, p string) any {
	return decode(t, `{"cve": "`+cve+`", "priority": "`+p+`", "status": "UNKNOWN", "host_count": 0,
		"rationale": "No Qualys KnowledgeBase CVE-to-QID mapping found",
		"sample_hosts": "", "qids": ""}`)
}

func presentRow(t *testing.T, cve string) any {
	return decode(t, `{"cve": "`+cve+`", "priority": "Sev4", "status": "PRESENT",
		"host_count": 3, "rationale": "PRESENT on 3 host(s)",
		"sample_hosts": "h1", "qids": "1"}`)
}

// Sev4 holds only confirmed presence, so its label may say so.
func TestSev4ClaimsPresenceBecauseOnlyPresenceLandsThere(t *testing.T) {
	mustContain(t, pri["Sev4"].label, "Confirmed present")
	mustNotContain(t, strings.ToLower(pri["Sev4"].label), "unverified")
}

// Sev3 and Sev2 hold UNKNOWN rows and neither label asserts presence.
func TestNoBandLabelClaimsPresenceForUnverifiedRows(t *testing.T) {
	for _, b := range []string{"Sev3", "Sev2"} {
		if strings.Contains(strings.ToLower(pri[b].label), "confirmed present") {
			t.Errorf("%s label claims presence: %q", b, pri[b].label)
		}
	}
}

// The severity scale is monotonic: Sev5 first, Sev1 last.
func TestTheScaleIsMonotonic(t *testing.T) {
	if !reflect.DeepEqual(SevOrder, []string{"Sev5", "Sev4", "Sev3", "Sev2", "Sev1"}) {
		t.Fatalf("SevOrder = %v", SevOrder)
	}
	order := map[string]int{}
	for i, p := range SevOrder {
		order[p] = i
	}
	for i := 0; i+1 < len(SevOrder); i++ {
		if order[SevOrder[i]] >= order[SevOrder[i+1]] {
			t.Errorf("%s does not outrank %s", SevOrder[i], SevOrder[i+1])
		}
	}
}

// Sev3 explains why it exists and claims no presence.
func TestSev3ExplainsWhyItExists(t *testing.T) {
	d := bandData([]any{unknownRow(t, "CVE-1", "Sev3")}, map[string]int{"Sev3": 1})
	html := render(d, "daily")
	mustContain(t, html, "it means nobody looked")
	mustNotContain(t, cut(strings.Split(html, "Sev3")[1], 400), "Confirmed present")
}

// A band of confirmed rows carries no caveat.
func TestAllPresentBandCarriesNoCaveat(t *testing.T) {
	d := bandData([]any{presentRow(t, "CVE-1"), presentRow(t, "CVE-2")}, map[string]int{"Sev4": 2})
	mustNotContain(t, render(d, "daily"), "nobody looked")
}

// The subject counts confirmed rows, not band size.
func TestSubjectCountsConfirmedPresenceNotBandSize(t *testing.T) {
	d := bandData([]any{unknownRow(t, "CVE-1", "Sev3"), unknownRow(t, "CVE-2", "Sev3")}, map[string]int{"Sev3": 2})
	s := subject(d, "daily")
	mustContain(t, s, "0 confirmed present")
	mustContain(t, s, "could not check")

	d = bandData([]any{presentRow(t, "CVE-1"), unknownRow(t, "CVE-2", "Sev3")}, map[string]int{"Sev4": 1, "Sev3": 1})
	s = subject(d, "daily")
	mustContain(t, s, "1 confirmed present")
	mustContain(t, s, "1 unverified")
}

// The text digest carries the same caveat.
func TestTextDigestCarriesTheSameCaveat(t *testing.T) {
	d := bandData([]any{presentRow(t, "CVE-1"), unknownRow(t, "CVE-2", "Sev3")}, map[string]int{"Sev4": 1, "Sev3": 1})
	txt := renderText(d, "daily")
	mustContain(t, txt, "unverified coverage")
	mustContain(t, txt, "not that we are clean")
}

// No band label collides with the P1-P4 incident scale.
func TestLabelNeverSaysP1ThroughP4(t *testing.T) {
	for b, v := range pri {
		for _, p := range []string{"P1", "P2", "P3", "P4"} {
			if strings.Contains(v.label, p) {
				t.Errorf("%s label mentions %s", b, p)
			}
		}
	}
}

// ------------------------------------------------------------- KevInTheDigest

func kevData(t *testing.T, kev string, sev5 int) obj {
	return decodeObj(t, `{"counts": {"Sev5": `+itoa(sev5)+`, "Sev4": 2, "Sev3": 0, "Sev2": 0, "Sev1": 0},
		"total": 3, "degraded": [], "source_meta": {}, "generated": "2026-09-15T06:00:00Z",
		"kev_deadlines": `+kev+`,
		"findings": [{"cve": "CVE-2026-1", "priority": "Sev5", "status": "PRESENT", "host_count": 12,
		              "rationale": "present", "sample_hosts": "a", "qids": "1"}]}`)
}

// An overdue deadline rides along but Sev5 still leads.
func TestSev5StillLeadsTheSubject(t *testing.T) {
	s := subject(kevData(t, `{"overdue": 2, "worst_overdue_days": 26, "overdue_cves": ["X", "Y"]}`, 1), "daily")
	if !strings.HasPrefix(s, "[Sev5]") {
		t.Errorf("subject %q does not lead with [Sev5]", s)
	}
	if !strings.Contains(s, "OVERDUE") {
		t.Errorf("the deadline should still ride along: %q", s)
	}
}

// With no Sev5, OVERDUE leads.
func TestOverdueLeadsWhenThereIsNoSev5(t *testing.T) {
	s := subject(kevData(t, `{"overdue": 2, "worst_overdue_days": 26, "overdue_cves": ["X", "Y"]}`, 0), "daily")
	if !strings.HasPrefix(s, "[OVERDUE]") {
		t.Errorf("subject %q does not lead with [OVERDUE]", s)
	}
}

// No deadline banner when nothing is due.
func TestNoBannerWhenNothingIsDue(t *testing.T) {
	html := render(kevData(t, `{"overdue": 0, "due_within_14d": 0}`, 1), "daily")
	mustNotContain(t, html, "remediation deadline")
	mustNotContain(t, html, "fall due within")
}

// The deadline banner and the degraded notice coexist.
func TestBannersCoexistWithTheDegradedNotice(t *testing.T) {
	d := kevData(t, `{"overdue": 1, "worst_overdue_days": 4, "overdue_cves": ["X"]}`, 1)
	d["degraded"] = []any{"KEV catalog"}
	html := render(d, "daily")
	mustContain(t, html, "DEGRADED")
	mustContain(t, html, "remediation deadline")
	if a, b := strings.Count(html, "<div"), strings.Count(html, "</div>"); a != b {
		t.Errorf("<div %d vs </div> %d", a, b)
	}
}

// An enriched file older than kev_deadlines still renders.
func TestMissingSummaryKeyDoesNotBreakRendering(t *testing.T) {
	d := kevData(t, `{}`, 1)
	delete(d, "kev_deadlines")
	if render(d, "daily") == "" || renderText(d, "daily") == "" || subject(d, "daily") == "" {
		t.Error("an empty rendering")
	}
}

// ---------------------------------------------------------- DigestTicketLinks

func ticketDir(t *testing.T) (enrichedPath, ticketsPath string) {
	dir := t.TempDir()
	enrichedPath = filepath.Join(dir, "enriched-2026-10-02.json")
	ticketsPath = filepath.Join(dir, "enriched-2026-10-02-tickets.json")
	writeFile(t, enrichedPath, `{"findings": [], "counts": {}}`)
	return enrichedPath, ticketsPath
}

// The ticket map is found beside the enriched file.
func TestTheMapIsFoundBesideTheEnrichedFile(t *testing.T) {
	e, tk := ticketDir(t)
	writeFile(t, tk, `{"tickets": {"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9"}}}`)
	if got := str(get(loadTickets(e)["CVE-1"], "key")); got != "CR-9" {
		t.Errorf("key = %q", got)
	}
}

// A missing map is silent, not an error.
func TestAMissingMapIsSilentNotAnError(t *testing.T) {
	e, _ := ticketDir(t)
	if got := loadTickets(e); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

// A corrupt map is silent too.
func TestACorruptMapIsSilentToo(t *testing.T) {
	e, tk := ticketDir(t)
	writeFile(t, tk, "{not json")
	if got := loadTickets(e); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

// The ticket key, link and status reach the HTML.
func TestTheKeyAndLinkReachTheHtml(t *testing.T) {
	tickets := decodeObj(t, `{"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9", "status": "In Progress"}}`)
	html := ticketCellHTML(obj{"cve": "CVE-1"}, tickets)
	mustContain(t, html, "CR-9")
	mustContain(t, html, "https://x/browse/CR-9")
	mustContain(t, html, "In Progress")
}

// A finding with no ticket renders nothing.
func TestAFindingWithNoTicketRendersNothing(t *testing.T) {
	if got := ticketCellHTML(obj{"cve": "CVE-2"}, obj{}); got != "" {
		t.Errorf("html = %q", got)
	}
	if got, ok := ticketCellText(obj{"cve": "CVE-2"}, obj{}); ok {
		t.Errorf("text = %q, want None", got)
	}
}

// Only http(s) ticket URLs become links.
func TestOnlyHttpUrlsBecomeLinks(t *testing.T) {
	tickets := decodeObj(t, `{"CVE-1": {"key": "CR-9", "url": "javascript:alert(1)"}}`)
	html := ticketCellHTML(obj{"cve": "CVE-1"}, tickets)
	mustNotContain(t, html, "javascript:")
	mustContain(t, html, "CR-9")
}

// The ticket key is escaped.
func TestTheTicketKeyIsEscaped(t *testing.T) {
	tickets := decodeObj(t, `{"CVE-1": {"key": "<script>", "url": ""}}`)
	mustNotContain(t, ticketCellHTML(obj{"cve": "CVE-1"}, tickets), "<script>")
}

// The text digest quotes the ticket too.
func TestTheTextDigestCarriesItToo(t *testing.T) {
	tickets := decodeObj(t, `{"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9"}}`)
	line, _ := ticketCellText(obj{"cve": "CVE-1"}, tickets)
	mustContain(t, line, "CR-9")
	mustContain(t, line, "https://x/browse/CR-9")
}

// ----------------------------------------------------------- DigestAdvisories

const advReport = `{
 "schema": "cti-advisories/1", "read": 3, "triaged": 2, "cost_usd": 0.0612,
 "gaps": ["not visible to Falcon: sites without the sensor"],
 "results": [
  {"subject": "Quiet one", "sender": "feed@example.com", "trusted_sender": true,
   "verdicts": {"sightings": [], "verdicts": [
     {"subject": "S1", "title": "7-Zip", "relevance": "unlikely", "reason": "not installed",
      "reason_by": "judge", "facts": []}]}},
  {"subject": "<script>x</script> hxxp://evil[.]example/a", "sender": "a@b.example",
   "trusted_sender": false, "problems": ["reader: no JSON object"],
   "verdicts": {"sightings": [{"value": "evil.example", "type": "domain", "hosts_seen_on": 2}],
                "verdicts": [{"subject": "S1", "title": "Campaign", "relevance": "possible",
                              "reason": "the domain was seen on 2 hosts", "reason_by": "judge",
                              "raised_by_code": "one of our hosts saw one of the advisory's indicators",
                              "facts": [{"id": "F1", "text": "indicator \"evil.example\" seen on 2"}],
                              "suggested_checks": ["isolate the 2 hosts"]}]}},
  {"subject": "Third", "sender": "c@d.example", "not_triaged": "over the cap of 2"},
  {"subject": "Re: lunch", "sender": "x@corp.example", "why": "1 public IP address(es)",
   "not_threat_intel": true, "verdicts": {"sightings": [], "verdicts": []}},
  {"subject": "CVE roundup", "sender": "feed@example.com", "trusted_sender": true,
   "cve_items": ["Chrome bug (CVE-2026-1)"],
   "verdicts": {"sightings": [], "verdicts": []}}
 ]}`

func advData(t *testing.T, withReport, enabled bool, kind string) obj {
	var rep any
	if withReport {
		rep = decode(t, advReport)
	}
	return obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now",
		"_advisories": rep, "_triage_enabled": enabled, "_kind": kind}
}

// A sighting comes first and every advisory read is listed.
func TestSightingsFirstAndEveryAdvisoryListed(t *testing.T) {
	txt := strings.Join(advisoriesText(advData(t, true, true, "daily")), "\n")
	mustContain(t, txt, "FLEET ADVISORIES - 3 threat-intel messages, 1 worth a look")
	if a, b := strings.Index(txt, "SEEN ON OUR HOSTS: evil.example"), strings.Index(txt, "Quiet one"); a < 0 || b < 0 || a >= b {
		t.Errorf("the sighting (%d) is not before the quiet one (%d)", a, b)
	}
	mustContain(t, txt, "Not triaged: over the cap of 2")
	mustContain(t, txt, "Raised by code:")
	mustContain(t, txt, "Check: isolate the 2 hosts")
	mustContain(t, txt, "a@b.example")
	mustContain(t, txt, "(a listed threat-intel sender)")
	mustContain(t, txt, "Read, no threat found: Re: lunch")
	mustNotContain(t, txt, "    from x@corp.example")
	mustContain(t, txt, "Model cost: $0.06")
	mustContain(t, txt, "In the CVE report above, not judged here: Chrome bug (CVE-2026-1)")
}

// Nothing from the advisories is markup or a link.
func TestNothingInItIsMarkupOrALink(t *testing.T) {
	html := advisoriesSection(advData(t, true, true, "daily"))
	mustNotContain(t, html, "<script>")
	mustContain(t, html, "&lt;script&gt;")
	mustNotContain(t, html, "<a ")
	mustNotContain(t, html, "href")
}

// The daily's own report never reaches the weekly: it has only the roll-up
// (advweek_test.go), which needs the week's reports Prepare reads.
func TestItReachesTheDailyAndNotTheWeekly(t *testing.T) {
	mustContain(t, render(advData(t, true, true, "daily"), "daily"), "FLEET ADVISORIES")
	mustContain(t, renderText(advData(t, true, true, "daily"), "daily"), "FLEET ADVISORIES")
	mustNotContain(t, render(advData(t, true, true, "weekly"), "weekly"), "FLEET ADVISORIES")
}

// No report says so when triage is on, and nothing when it is off.
func TestMissingReport(t *testing.T) {
	mustContain(t, advisoriesSection(advData(t, false, true, "daily")), "reported nothing today")
	if got := advisoriesSection(advData(t, false, false, "daily")); got != "" {
		t.Errorf("section = %q", got)
	}
	if got := advisoriesText(advData(t, false, false, "daily")); len(got) != 0 {
		t.Errorf("text = %q", got)
	}
}

// load_advisories rejects anything but a cti-advisories/1 report.
func TestLoadAdvisoriesRejectsOtherShapes(t *testing.T) {
	d := t.TempDir()
	e := filepath.Join(d, "enriched-x.json")
	if got := loadAdvisories(e); got != nil {
		t.Errorf("missing: got %v", got)
	}
	path := filepath.Join(d, "enriched-x-advisories.json")
	for _, bad := range []string{"not json", `{"schema": "cti-advisories/2", "results": []}`, `{"schema": "cti-advisories/1"}`} {
		writeFile(t, path, bad)
		if got := loadAdvisories(e); got != nil {
			t.Errorf("%s: got %v", bad, got)
		}
	}
	writeFile(t, path, advReport)
	if got := str(get(loadAdvisories(e), "read")); got != "3" {
		t.Errorf("read = %q", got)
	}
}

// --------------------------------------------------------- DigestFleetTickets

const fleetTicketsJSON = `{
 "CVE-2026-1": {"key": "CR-10", "url": "https://x/browse/CR-10", "status": "In Progress",
                "cve": "CVE-2026-1", "checked": true, "hosts": 0,
                "outcome": "commented: no detections remain (was 12) - this ticket can be closed"},
 "CVE-2026-2": {"key": "CR-9", "url": "https://x/browse/CR-9", "status": "Open",
                "cve": "CVE-2026-2", "checked": true, "hosts": 227,
                "outcome": "no change since the last report (227 host(s)) - no comment"},
 "CVE-2026-3": {"key": "CR-11", "url": "https://x/browse/CR-11", "status": "Done",
                "done": true, "cve": "CVE-2026-3", "checked": true, "hosts": 0},
 "CVE-2026-4": {"key": "CR-12", "url": "javascript:alert(1)", "status": "<b>New</b>",
                "outcome": "not re-checked: the scanner lookup failed"}}`

func ticketsData(t *testing.T, tickets string) obj {
	if tickets == "" {
		tickets = fleetTicketsJSON
	}
	return obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now",
		"_tickets": decode(t, tickets)}
}

func keysOf(rows []obj) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, str(r["key"]))
	}
	return out
}

// Every ticket is listed, open first, in key order.
func TestEveryTicketIsListedOpenFirstInKeyOrder(t *testing.T) {
	open, closed := fleetTickets(ticketsData(t, ""))
	if got := keysOf(open); !reflect.DeepEqual(got, []string{"CR-9", "CR-10", "CR-12"}) {
		t.Errorf("open = %v", got)
	}
	if got := keysOf(closed); !reflect.DeepEqual(got, []string{"CR-11"}) {
		t.Errorf("closed = %v", got)
	}
}

// The HTML says what the daily re-check found.
func TestTheHtmlSaysWhatTheRecheckFound(t *testing.T) {
	html := fleetTicketsSection(ticketsData(t, ""))
	mustContain(t, html, "FLEET TICKETS &mdash; 3 open")
	mustContain(t, html, "no detections remain")
	mustContain(t, html, "227 hosts")
	mustContain(t, html, "not re-checked")
	mustContain(t, html, "Closed in the last 30 days")
	mustNotContain(t, html, "javascript:")
	mustNotContain(t, html, "<b>New</b>")
}

// Fleet tickets reach the rendered daily even with no findings.
func TestItReachesTheRenderedDailyEvenWithNoFindings(t *testing.T) {
	mustContain(t, render(ticketsData(t, ""), "daily"), "FLEET TICKETS")
	txt := renderText(ticketsData(t, ""), "daily")
	mustContain(t, txt, "FLEET TICKETS - 3 open")
	mustContain(t, txt, "CR-9")
	mustContain(t, txt, "227 hosts")
}

// The domains lock-down ticket is shown as such.
func TestTheDomainsLockDownTicketIsShownAsSuch(t *testing.T) {
	html := fleetTicketsSection(ticketsData(t, `{"DNS lock-down": {"key": "CR-50", "url": "https://x/browse/CR-50",
		"status": "Open", "kind": "domains-lockdown", "outcome": "the weekly domains lock-down ticket"}}`))
	mustContain(t, html, "DNS lock-down")
	mustContain(t, html, "DNS changes for IT")
	mustNotContain(t, html, "not re-checked")
}

// The VM scan spreadsheet ticket is shown as such.
func TestTheSpreadsheetTicketIsShownAsSuch(t *testing.T) {
	d := ticketsData(t, `{"Spreadsheet fixes": {"key": "CR-77", "url": "https://x/browse/CR-77", "status": "Open",
		"kind": "vmscan-sheet-fixes",
		"outcome": "the network team's spreadsheet ticket - updated by the weekly VM scan run"}}`)
	html := fleetTicketsSection(d)
	mustContain(t, html, "CR-77")
	mustContain(t, html, "Spreadsheet fixes")
	mustContain(t, html, "spreadsheet fixes for the network team")
	mustNotContain(t, html, "not re-checked")
	txt := strings.Join(fleetTicketsText(d), "\n")
	mustContain(t, txt, "spreadsheet fixes for the network team")
	mustNotContain(t, txt, "Product:")
}

// Supplier requests are one summary line, not a row each.
func TestSupplierItemsAreOneSummaryLine(t *testing.T) {
	item := func(key string, done bool) string {
		status, d := "To Do", "false"
		if done {
			status, d = "Done", "true"
		}
		return `{"key": "` + key + `", "url": "https://x/browse/` + key + `", "status": "` + status +
			`", "cve": "Supplier request", "kind": "supplier-request", "done": ` + d + `}`
	}
	tk := `{"supplier:CR-81": ` + item("CR-81", false) + `, "supplier:CR-83": ` + item("CR-83", false) +
		`, "supplier:CR-84": ` + item("CR-84", true) + `}`
	html := fleetTicketsSection(ticketsData(t, tk))
	mustContain(t, html, "2 Supplier request tickets opened for TPRM evaluation")
	if strings.Contains(html, "CR-81") {
		t.Error("supplier items are a count, not a row each")
	}
	txt := strings.Join(fleetTicketsText(ticketsData(t, tk)), "\n")
	mustContain(t, txt, "2 Supplier request tickets opened for TPRM evaluation")
	one := `{"supplier:CR-81": ` + item("CR-81", false) + `}`
	mustContain(t, fleetTicketsSection(ticketsData(t, one)), "1 Supplier request ticket opened")
}

// Other fleet tickets are shown, listed and not re-checked.
func TestOtherFleetTicketsAreShown(t *testing.T) {
	html := fleetTicketsSection(ticketsData(t, `{"fleet:CR-82": {"key": "CR-82", "url": "https://x/browse/CR-82",
		"status": "Open", "cve": "Fleet ticket", "kind": "fleet-other",
		"outcome": "a fleet ticket this daily re-check does not cover"}}`))
	for _, want := range []string{"CR-82", "Fleet ticket", "listed, not re-checked"} {
		mustContain(t, html, want)
	}
}

// No tickets, no section.
func TestNoTicketsNoSection(t *testing.T) {
	if got := fleetTicketsSection(ticketsData(t, `{}`)); got != "" {
		t.Errorf("section = %q", got)
	}
	mustNotContain(t, renderText(ticketsData(t, `{}`), "daily"), "FLEET TICKETS")
}

// A ticket map from before the re-check fields still renders.
func TestAnOldMapWithoutTheNewFieldsStillRenders(t *testing.T) {
	html := fleetTicketsSection(ticketsData(t, `{"CVE-1": {"key": "CR-9", "url": "https://x/browse/CR-9", "status": "Open"}}`))
	mustContain(t, html, "CR-9")
	mustContain(t, html, "CVE-1")
	mustContain(t, html, "not re-checked")
}

// The heading claims only the re-check that actually happened.
func TestTheHeadingClaimsOnlyTheRecheckThatHappened(t *testing.T) {
	sheet := `{"VM scan spreadsheet": {"key": "HD-7", "url": "https://x/browse/HD-7", "status": "Open",
		"kind": "vmscan-sheet-fixes",
		"outcome": "the network team's spreadsheet ticket - updated by the weekly VM scan run"}}`
	for _, c := range []struct {
		name  string
		extra obj
		want  string
	}{
		{"daily", obj{}, "re-checked against the scanner today"},
		{"weekly", obj{"_kind": "weekly"}, "as the latest daily re-checked them"},
		{"listed only", obj{"_tickets_listed_only": true}, "not re-checked against the scanner this run"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := ticketsData(t, sheet)
			for k, v := range c.extra {
				d[k] = v
			}
			html := fleetTicketsSection(d)
			text := strings.Join(fleetTicketsText(d), "\n")
			for _, out := range []string{html, text} {
				mustContain(t, out, c.want)
				mustContain(t, out, "HD-7")
				mustContain(t, out, "spreadsheet fixes for the network team")
			}
			if len(c.extra) > 0 {
				mustNotContain(t, html, "re-checked against the scanner today")
			}
			mustContain(t, html, `href="https://x/browse/HD-7"`)
		})
	}
}

// The listed-only flag is read from the ticket map.
func TestTheListedOnlyFlagIsReadFromTheMap(t *testing.T) {
	e := filepath.Join(t.TempDir(), "weekly-enriched-2026-11-16.json")
	writeFile(t, strings.TrimSuffix(e, ".json")+"-tickets.json",
		`{"generated": "now", "listed_only": true, "tickets": {"x": {"key": "HD-7", "kind": "vmscan-sheet-fixes"}}}`)
	if !truthy(ticketMap(e)["listed_only"]) {
		t.Error("listed_only not read")
	}
	if got := str(get(loadTickets(e)["x"], "key")); got != "HD-7" {
		t.Errorf("key = %q", got)
	}
}

// ------------------------------------------------------------ HeldForApproval

const heldJSON = `[{"cve": "CVE-2026-111497", "hosts": 14, "title": "Some <b>exploit</b>"}]`

func heldData(t *testing.T, held, enrichedPath string) obj {
	if held == "" {
		held = heldJSON
	}
	return obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now",
		"_tickets": obj{}, "_held": decode(t, held), "_enriched": enrichedPath}
}

func heldPaths(t *testing.T) (enrichedPath, ticketsPath string) {
	dir := t.TempDir()
	return filepath.Join(dir, "enriched-2026-10-02.json"), filepath.Join(dir, "enriched-2026-10-02-tickets.json")
}

// The held CVE, its hosts and the approve command reach the HTML.
func TestTheHeldCveTheHostsAndTheCommandReachTheHtml(t *testing.T) {
	e, _ := heldPaths(t)
	html := heldSection(heldData(t, "", e))
	mustContain(t, html, "HELD FOR APPROVAL")
	mustContain(t, html, "CVE-2026-111497")
	mustContain(t, html, "14 hosts")
	mustContain(t, html, "--for-real --approve")
	mustContain(t, html, e)
}

// Held titles are escaped.
func TestTitlesAreEscaped(t *testing.T) {
	e, _ := heldPaths(t)
	mustNotContain(t, heldSection(heldData(t, "", e)), "<b>exploit</b>")
}

// The text digest names the held CVE too.
func TestTheTextDigestNamesItToo(t *testing.T) {
	e, _ := heldPaths(t)
	text := renderText(heldData(t, "", e), "daily")
	mustContain(t, text, "HELD FOR APPROVAL")
	mustContain(t, text, "CVE-2026-111497")
	mustContain(t, text, "--approve")
}

// Nothing held means no section.
func TestNothingHeldMeansNoSection(t *testing.T) {
	e, _ := heldPaths(t)
	if got := heldSection(heldData(t, `[]`, e)); got != "" {
		t.Errorf("section = %q", got)
	}
	mustNotContain(t, renderText(heldData(t, `[]`, e), "daily"), "HELD FOR APPROVAL")
}

// load_held reads the map and survives a bad one.
func TestLoadHeldReadsTheMapAndSurvivesABadOne(t *testing.T) {
	e, tk := heldPaths(t)
	held := decode(t, heldJSON)
	writeFile(t, tk, `{"tickets": {}, "held": [{"cve": "CVE-2026-111497", "hosts": 14, "title": "Some <b>exploit</b>"}, "junk", {"hosts": 2}]}`)
	if got := loadHeld(ticketMap(e)); !reflect.DeepEqual(got, held) {
		t.Errorf("held = %v, want %v", got, held)
	}
	writeFile(t, tk, `{"tickets": {}, "held": "nope"}`)
	if got := loadHeld(ticketMap(e)); len(got) != 0 {
		t.Errorf("held = %v", got)
	}
	writeFile(t, tk, `["not", "a", "dict"]`)
	if got := loadHeld(ticketMap(e)); len(got) != 0 {
		t.Errorf("held = %v", got)
	}
	if got := loadTickets(e); len(got) != 0 {
		t.Errorf("tickets = %v", got)
	}
	if err := os.Remove(tk); err != nil {
		t.Fatal(err)
	}
	if got := loadHeld(ticketMap(e)); len(got) != 0 {
		t.Errorf("held = %v", got)
	}
}

// ---------------------------------------------------------------- ProductName

func productFinding(t *testing.T, extra string) obj {
	f := decodeObj(t, `{"cve": "CVE-2026-9", "priority": "Sev5", "status": "PRESENT", "host_count": 3, "rationale": "r"}`)
	if extra != "" {
		for k, v := range decodeObj(t, extra) {
			f[k] = v
		}
	}
	return f
}

// The product map beside the enriched file is read.
func TestBriefReadsTheProductMapBesideTheEnrichedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "products.json"), `{"fetched": "2026-11-22T06:00:00.000000+00:00", "data": {
		"CVE-2026-1": "PHP", "CVE-2026-2": "Apple Safari", "CVE-2026-3": "Node.js"}}`)
	got := loadProducts(filepath.Join(dir, "enriched-x.json"))
	want := obj{"CVE-2026-1": "PHP", "CVE-2026-2": "Apple Safari", "CVE-2026-3": "Node.js"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("products = %v", got)
	}
}

// The finding card highlights the product, escaped, with its source.
func TestTheCardHighlightsTheProduct(t *testing.T) {
	html := findingBlock(productFinding(t, `{"product": "Google <Chrome>", "product_source": "NVD"}`), nil, false)
	mustContain(t, html, "Google &lt;Chrome&gt;")
	mustContain(t, html, `title="from NVD"`)
}

// The card says when no product was found.
func TestTheCardSaysWhenNoProductWasFound(t *testing.T) {
	mustContain(t, findingBlock(productFinding(t, `{"product": ""}`), nil, false), "product not identified")
}

// A row from before the field renders as before.
func TestAnOldRowWithoutTheFieldRendersAsBefore(t *testing.T) {
	mustNotContain(t, findingBlock(productFinding(t, ""), nil, false), "product not identified")
}

// Fleet tickets name the product, from today's findings or the map.
func TestFleetTicketsNameTheProductFromTheMap(t *testing.T) {
	d := obj{"findings": []any{productFinding(t, `{"cve": "CVE-2026-1", "product": "PHP"}`)},
		"counts": obj{}, "total": json.Number("1"), "generated": "now",
		"_products": obj{"CVE-2026-2": "Apple Safari"},
		"_tickets": decode(t, `{
			"CVE-2026-1": {"key": "CR-1", "cve": "CVE-2026-1", "status": "Open"},
			"CVE-2026-2": {"key": "CR-2", "cve": "CVE-2026-2", "status": "Open"},
			"CVE-2026-3": {"key": "CR-3", "cve": "CVE-2026-3", "status": "Open"}}`)}
	html := fleetTicketsSection(d)
	mustContain(t, html, "PHP")
	mustContain(t, html, "Apple Safari")
	txt := strings.Join(fleetTicketsText(d), "\n")
	mustContain(t, txt, "Product: PHP")
	mustContain(t, txt, "Product: Apple Safari")
	if n := strings.Count(txt, "Product:"); n != 2 {
		t.Errorf("Product: appears %d times, want 2", n)
	}
}

// The text digest names the product.
func TestTheTextDigestNamesTheProduct(t *testing.T) {
	d := obj{"findings": []any{productFinding(t, `{"product": "PHP"}`)}, "counts": obj{"Sev5": json.Number("1")},
		"total": json.Number("1"), "generated": "now"}
	mustContain(t, renderText(d, "daily"), "CVE-2026-9  [PHP]")
}

// ---------------------------------------------- WeeklyIsDistinguishableFromDaily

func subjectCases(t *testing.T) map[string]obj {
	return map[string]obj{
		"quiet": decodeObj(t, `{"counts": {}, "total": 0, "findings": [], "kev_deadlines": {}}`),
		"sev5": decodeObj(t, `{"counts": {"Sev5": 4}, "total": 9, "findings": [],
			"kev_deadlines": {"overdue": 4, "worst_overdue_days": 12}}`),
		"overdue only": decodeObj(t, `{"counts": {}, "total": 3, "findings": [],
			"kev_deadlines": {"overdue": 2, "worst_overdue_days": 5}}`),
		"present": decodeObj(t, `{"counts": {}, "total": 5, "kev_deadlines": {},
			"findings": [{"status": "PRESENT", "host_count": 3, "priority": "Sev3"}]}`),
		"unverified": decodeObj(t, `{"counts": {}, "total": 4, "kev_deadlines": {},
			"findings": [{"status": "UNKNOWN", "priority": "Sev3"}]}`),
		"reviewed": decodeObj(t, `{"counts": {}, "total": 7, "findings": [], "kev_deadlines": {}}`),
	}
}

// No subject branch gives the daily and the weekly the same subject.
func TestNoBranchProducesTheSameSubjectForBothKinds(t *testing.T) {
	for name, d := range subjectCases(t) {
		if daily, weekly := subject(d, "daily"), subject(d, "weekly"); daily == weekly {
			t.Errorf("%s: daily and weekly subjects are identical - %q", name, daily)
		}
	}
}

// The weekly subject says Weekly.
func TestTheWeeklySaysWeekly(t *testing.T) {
	for name, d := range subjectCases(t) {
		if s := subject(d, "weekly"); !strings.Contains(s, "Weekly") {
			t.Errorf("%s: %q does not say it is weekly", name, s)
		}
	}
}

// Neither subject claims the other's window.
func TestNeitherKindClaimsTheWrongWindow(t *testing.T) {
	quiet := subjectCases(t)["quiet"]
	mustContain(t, subject(quiet, "daily"), "24h")
	if s := subject(quiet, "weekly"); strings.Contains(s, "24h") {
		t.Errorf("the weekly subject claims a 24-hour window: %q", s)
	}
	mustContain(t, subject(quiet, "weekly"), "7 days")
}

// ---------------------------------------------------------------- EmailTokens
// The Go port reads its palette from internal/emailkit, so these hold the
// renderer to emailkit rather than to fleet-kit's email-tokens.json.

// The severity bands use the shared tones.
func TestTheSeverityBandsUseTheSharedTones(t *testing.T) {
	for sev, tone := range map[string]emailkit.Tone{"Sev5": emailkit.Red, "Sev4": emailkit.Amber,
		"Sev3": emailkit.Yellow, "Sev2": emailkit.Blue, "Sev1": emailkit.Grey} {
		if pri[sev].fg != tone.Fg || pri[sev].bg != tone.Bg {
			t.Errorf("%s: (%s, %s), want (%s, %s)", sev, pri[sev].fg, pri[sev].bg, tone.Fg, tone.Bg)
		}
	}
}

// The digest page is drawn from the tokens.
func TestTheDigestPageIsDrawnFromTheTokens(t *testing.T) {
	d := decodeObj(t, `{"counts": {}, "findings": [], "total": 0, "generated": "now", "source_meta": {}}`)
	html := render(d, "daily")
	for name, v := range map[string]string{"navy": emailkit.Navy, "page_bg": emailkit.PageBG, "band_text": emailkit.BandText} {
		if !strings.Contains(html, v) {
			t.Errorf("%s (%s) is not in the page", name, v)
		}
	}
}
