package patchtuesday

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cvrfFixture is a synthetic month in the real document's shape: field names,
// note and threat types, and revision dates out of order, as the API serves
// them. Every entry is there to be kept or dropped for one stated reason.
const cvrfFixture = `{
 "DocumentTitle": {"Value": "September 2026 Security Updates"},
 "DocumentTracking": {"InitialReleaseDate": "2026-09-08T07:00:00"},
 "Vulnerability": [
  {"Title": {"Value": "Windows Kernel Remote Code Execution Vulnerability"},
   "CVE": "CVE-2026-1001",
   "Notes": [{"Title": "Windows Kernel", "Type": 7, "Value": "Windows Kernel"},
             {"Title": "Microsoft", "Type": 8, "Value": "Microsoft"},
             {"Title": "Customer Action Required", "Type": 6, "Value": "Yes"}],
   "Threats": [{"Description": {"Value": "Remote Code Execution"}, "Type": 0},
               {"Description": {"Value": "Critical"}, "Type": 3},
               {"Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"}, "Type": 1}],
   "RevisionHistory": [{"Date": "2026-09-08T07:00:00"}]},

  {"Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
   "CVE": "CVE-2026-1002",
   "Notes": [{"Title": "Windows Kernel", "Type": 7, "Value": "Windows Kernel"},
             {"Title": "Microsoft", "Type": 8, "Value": "Microsoft"}],
   "Threats": [{"Description": {"Value": "Elevation of Privilege"}, "Type": 0},
               {"Description": {"Value": "Important"}, "Type": 3},
               {"Description": {"Value": "Publicly Disclosed:Yes;Exploited:No"}, "Type": 1}],
   "RevisionHistory": [{"Date": "2026-09-20T01:00:00"}, {"Date": "2026-09-08T07:00:00"}]},

  {"Title": {"Value": "Azure Portal Spoofing Vulnerability"},
   "CVE": "CVE-2026-1003",
   "Notes": [{"Title": "Azure Portal", "Type": 7, "Value": "Azure Portal"},
             {"Title": "Microsoft", "Type": 8, "Value": "Microsoft"},
             {"Title": "Customer Action Required", "Type": 6, "Value": "No"}],
   "Threats": [{"Description": {"Value": "Important"}, "Type": 3}],
   "RevisionHistory": [{"Date": "2026-09-08T07:00:00"}]},

  {"Title": {"Value": "Microsoft Edge (Chromium-based) Spoofing Vulnerability"},
   "CVE": "CVE-2026-1004",
   "Notes": [{"Title": "Microsoft Edge (Chromium-based)", "Type": 7, "Value": "Microsoft Edge (Chromium-based)"},
             {"Title": "Microsoft", "Type": 8, "Value": "Microsoft"}],
   "Threats": [{"Description": {"Value": "Moderate"}, "Type": 3}],
   "RevisionHistory": [{"Date": "2026-09-15T07:00:00"}]},

  {"Title": {"Value": "Packet overread in a Linux package"},
   "CVE": "CVE-2025-9999",
   "Notes": [{"Title": "Mariner", "Type": 7, "Value": "Mariner"},
             {"Title": "Linux", "Type": 8, "Value": "Linux"}],
   "Threats": [{"Description": {"Value": "Low"}, "Type": 3}],
   "RevisionHistory": [{"Date": "2026-09-08T07:00:00"}]},

  {"Title": {"Value": "Windows SMB Remote Code Execution Vulnerability"},
   "CVE": "cve-2026-1005",
   "Notes": [{"Title": "Microsoft", "Type": 8, "Value": "Microsoft"}],
   "Threats": [{"Description": {"Value": "Important"}, "Type": 3},
               {"Description": {"Value": "Critical"}, "Type": 3}],
   "RevisionHistory": [{"Date": "2026-09-08T18:30:00"}]},

  {"Title": {"Value": "duplicate"},
   "CVE": "CVE-2026-1001",
   "Notes": [{"Title": "Microsoft", "Type": 8, "Value": "Microsoft"}],
   "Threats": [{"Description": {"Value": "Low"}, "Type": 3}],
   "RevisionHistory": [{"Date": "2026-09-08T07:00:00"}]}
 ]
}`

func fixtureRelease(t *testing.T) *Release {
	t.Helper()
	rel, err := ParseMSRC(strings.NewReader(cvrfFixture), 2026, time.September)
	if err != nil {
		t.Fatalf("ParseMSRC: %v", err)
	}
	return rel
}

func TestParseMSRCKeepsOnlyTheRelease(t *testing.T) {
	rel := fixtureRelease(t)
	// 1001 and 1002 (first published on the day, despite the out-of-order
	// revision list) and 1005 (lower-case ID, published later the same day).
	// Not 1003 (cloud-only), 1004 (published a week later), 2025-9999
	// (another CNA), or the duplicate 1001.
	want := []string{"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1005"}
	if strings.Join(rel.CVEs, ",") != strings.Join(want, ",") {
		t.Errorf("CVEs = %v, want %v", rel.CVEs, want)
	}
	if rel.Total != 3 || rel.CloudOnly != 1 {
		t.Errorf("Total=%d CloudOnly=%d, want 3 and 1", rel.Total, rel.CloudOnly)
	}
	// 1005 carries both Important and Critical threats: the worst wins.
	if rel.Critical != 2 || rel.Important != 1 {
		t.Errorf("Critical=%d Important=%d, want 2 and 1", rel.Critical, rel.Important)
	}
	if strings.Join(rel.Exploited, ",") != "CVE-2026-1001" {
		t.Errorf("Exploited = %v", rel.Exploited)
	}
	if strings.Join(rel.Disclosed, ",") != "CVE-2026-1002" {
		t.Errorf("Disclosed = %v", rel.Disclosed)
	}
	if rel.Tags["Windows Kernel"] != 2 {
		t.Errorf("Tags = %v", rel.Tags)
	}
}

func TestMSRCZeroDaySentenceNamesTheCVEs(t *testing.T) {
	s := fixtureRelease(t).ZeroDaySentence()
	for _, want := range []string{
		"1 vulnerability as exploited",
		"CVE-2026-1001 (Windows Kernel Remote Code Execution Vulnerability)",
		"1 is marked publicly disclosed: CVE-2026-1002",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("sentence lacks %q:\n%s", want, s)
		}
	}
	none := (&Release{}).ZeroDaySentence()
	if !strings.Contains(none, "none of this month's") || !strings.Contains(none, "None are marked") {
		t.Errorf("empty release sentence = %q", none)
	}
}

func TestMSRCCategoriesAreByImpact(t *testing.T) {
	cats := fixtureRelease(t).Categories()
	got := map[string]Category{}
	for _, c := range cats {
		got[c.Name] = c
	}
	if c := got["Remote Code Execution Vulnerabilities"]; c.Quantity != 1 || c.Severities != "Critical: 1" {
		t.Errorf("RCE = %+v", c)
	}
	// 1005 has no impact threat; it is counted, under Other, not dropped.
	if c := got["Other Vulnerabilities"]; c.Quantity != 1 {
		t.Errorf("Other = %+v (all: %+v)", c, cats)
	}
}

func TestParseMSRCRefusesADocumentItCannotRead(t *testing.T) {
	if _, err := ParseMSRC(strings.NewReader("<cvrf/>"), 2026, time.September); err == nil {
		t.Error("XML was accepted as the JSON document")
	}
	// Entries, but none recognisable: a format change, never "a quiet month".
	odd := `{"Vulnerability":[{"CVE":"CVE-2026-1","RevisionHistory":[{"Date":"2026-09-08T07:00:00"}]}]}`
	if _, err := ParseMSRC(strings.NewReader(odd), 2026, time.September); err == nil ||
		!strings.Contains(err.Error(), "format may have changed") {
		t.Errorf("err = %v", err)
	}
}

func TestMSRCURLs(t *testing.T) {
	if got := MSRCID(2026, time.September); got != "2026-Sep" {
		t.Errorf("MSRCID = %q", got)
	}
	if got := MSRCAPIURL(2026, time.October); got != "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct" {
		t.Errorf("MSRCAPIURL = %q", got)
	}
	if !strings.HasSuffix(MSRCPageURL(2026, time.May), "/releaseNote/2026-May") {
		t.Errorf("MSRCPageURL = %q", MSRCPageURL(2026, time.May))
	}
}

func TestFetchMSRCAsksForJSONAndLinksTheHumanPage(t *testing.T) {
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.NotFound(w, r)
			return
		}
		accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cvrfFixture))
	}))
	defer srv.Close()

	s, rel := FetchMSRC(context.Background(), srv.Client(), srv.URL+"/doc", 2026, time.September)
	if !s.Fetched || rel == nil || rel.Total != 3 {
		t.Fatalf("source=%+v rel=%+v", s, rel)
	}
	if accept != "application/json" {
		t.Errorf("Accept = %q; without it the API answers XML", accept)
	}
	if s.URL != MSRCPageURL(2026, time.September) || s.Role != RoleMSRC {
		t.Errorf("source = %+v", s)
	}

	s, rel = FetchMSRC(context.Background(), srv.Client(), srv.URL+"/missing", 2026, time.September)
	if s.Fetched || rel != nil || !strings.Contains(s.Err, "not published") {
		t.Errorf("404: source=%+v", s)
	}
}

func TestMicrosoftsFiguresWinAndTheArticlesAreCrossChecked(t *testing.T) {
	rel := fixtureRelease(t)
	dg := parsed(t) // the August articles: Qualys says 421, BleepingComputer 400
	dg.MSRC = rel
	Parse(dg)

	if dg.Total != 3 || dg.Critical != 2 || dg.From["total"] != MSRCName {
		t.Errorf("Total=%d Critical=%d from %q", dg.Total, dg.Critical, dg.From["total"])
	}
	if strings.Join(dg.CVEs, ",") != strings.Join(rel.CVEs, ",") {
		t.Errorf("CVEs = %v, want Microsoft's %v", dg.CVEs, rel.CVEs)
	}
	if !strings.Contains(dg.ZeroDayText, "CVE-2026-1001") {
		t.Errorf("zero-days not Microsoft's: %q", dg.ZeroDayText)
	}
	// The QQL and the Edge count only the articles carry; they survive.
	if len(dg.SourceQQL) == 0 || dg.EdgeFixes != 128 {
		t.Errorf("lost article-only fields: QQL=%v Edge=%d", dg.SourceQQL, dg.EdgeFixes)
	}
	joined := strings.Join(dg.CrossCheck, "\n")
	for _, want := range []string{"BleepingComputer Patch Tuesday counts 400",
		"counts 421", "plus 1 already fixed in Microsoft's cloud"} {
		if !strings.Contains(joined, want) {
			t.Errorf("cross-check lacks %q:\n%s", want, joined)
		}
	}
	if dg.CVECountNote() != "" {
		t.Errorf("count note fired against Microsoft's own list: %q", dg.CVECountNote())
	}
	txt := (&Report{Digest: dg, Org: "Example Org"}).Text()
	if !strings.Contains(txt, "Counts are Microsoft's own") {
		t.Errorf("text does not say what the count is:\n%s", txt)
	}
}

func TestCrossCheckIsQuietWhenThePublisherAgrees(t *testing.T) {
	rel := fixtureRelease(t)
	dg := &Digest{Year: 2026, Month: time.September, MSRC: rel, Sources: []Source{
		{Name: "BleepingComputer Patch Tuesday", Role: RoleBleeping, Fetched: true,
			Text: "Microsoft's September 2026 Patch Tuesday fixes 4 flaws."},
	}}
	Parse(dg) // 4 = 3 needing action + 1 cloud-only: agreement
	if len(dg.CrossCheck) != 0 {
		t.Errorf("CrossCheck = %v", dg.CrossCheck)
	}
}

func TestAnOptionalSourceThatFailsIsNotIncomplete(t *testing.T) {
	dg := parsed(t)
	dg.Sources[0].Fetched = false // the Qualys blog
	dg.Sources[0].Err = "HTTP 403"
	dg.Sources[0].Optional = true
	if deg := dg.Degraded(); len(deg) != 0 {
		t.Errorf("Degraded = %v", deg)
	}
	txt := (&Report{Digest: dg, Org: "Example Org"}).Text()
	if strings.Contains(txt, "INCOMPLETE") {
		t.Error("an optional source made the report incomplete")
	}
	if !strings.Contains(txt, "(optional, not read: HTTP 403)") {
		t.Errorf("source list does not say the optional source was not read:\n%s", txt)
	}
}

func TestTheBannerSaysWhatTheReportWasBuiltFrom(t *testing.T) {
	dg := &Digest{Year: 2026, Month: time.September, Sources: []Source{
		{Name: MSRCName, Role: RoleMSRC, Err: "HTTP 503"},
		{Name: "BleepingComputer Patch Tuesday", Role: RoleBleeping, Fetched: true},
		{Name: "Qualys blog", Role: RoleQualysBlog, Optional: true, Err: "HTTP 403"},
	}}
	want := "Built from BleepingComputer Patch Tuesday only; could not read " +
		MSRCName + " (HTTP 503)."
	if got := dg.IncompleteSentence(); got != want {
		t.Errorf("banner = %q\nwant     %q", got, want)
	}
	r := &Report{Digest: dg, Org: "Example Org", Exposure: Unmeasured("not queried in this test")}
	if !strings.Contains(r.HTML(), "Built from BleepingComputer") {
		t.Error("HTML banner does not say what it was built from")
	}
}

func TestExplainUsesMicrosoftsList(t *testing.T) {
	dg := parsed(t)
	dg.MSRC = fixtureRelease(t)
	Parse(dg)
	if got := dg.Explain("CVE-2026-1001"); !strings.Contains(got, "is in Microsoft's release (2026-Sep)") {
		t.Errorf("Explain(in) = %q", got)
	}
	if got := dg.Explain("CVE-2026-3333"); !strings.Contains(got, "is NOT in Microsoft's release") {
		t.Errorf("Explain(out) = %q", got)
	}
}
