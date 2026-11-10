package appscan

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// sampleOwnerReport is the shape of a real report (a WordPress site, 9 Nov
// 2026), with the names made up: one potential Urgent from a plugin version,
// two cookie findings in eight places each, header weaknesses and
// diagnostics.
func sampleOwnerReport() OwnerReportInput {
	fin := time.Date(2026, 11, 9, 23, 46, 0, 0, time.UTC)
	cookie := func(qid, title, param, status string, cwe int) Finding {
		return Finding{ID: qid, Title: title, Severity: 2, URL: "https://www.example.com/", Param: param,
			Status: status, LastSeen: fin, Kind: "VULNERABILITY", CVSS: 4.3, CWE: []int{cwe}, QDS: 50,
			OWASP: []OWASPRef{{Code: "A02", Name: "A02:2025 Security Misconfiguration"}}}
	}
	fs := []Finding{{
		ID: "530636", Title: "WordPress Example Forms Plugin: Arbitrary File Upload (CVE-2025-12352)",
		Severity: 5, Potential: true, Status: "REOPENED", LastSeen: fin, Kind: "VULNERABILITY",
		URL:  "https://www.example.com/wp-content/plugins/forms/languages/forms.pot",
		CVSS: 9.8, CWE: []int{434}, QDS: 95, OWASP: []OWASPRef{{Code: "A06"}},
		Evidence: &Evidence{Method: "GET", Link: "https://www.example.com/wp-content/plugins/forms/languages/forms.pot",
			Proof:      "HTTP/2 200\nset-cookie: [redacted by cti-agent]\n\"Project-Id-Version: Forms 2.7.1\"",
			AccessPath: []string{"http://www.example.com/"}},
	}}
	for _, p := range []string{"sbjs_udata", "sbjs_session", "_ga_X"} {
		fs = append(fs, cookie("150123", `Cookie Does Not Contain The "HTTPOnly" Attribute`, p, "ACTIVE", 1004))
		fs = append(fs, cookie("150122", `Cookie Does Not Contain The "secure" Attribute`, p, "REOPENED", 614))
	}
	fs = append(fs,
		Finding{ID: "150938", Title: "Possible DOM XSS", Severity: 3, Kind: "INFORMATION_GATHERED"},
		Finding{ID: "150135", Title: "HSTS header missing", Severity: 2, Kind: "INFORMATION_GATHERED"},
		Finding{ID: "150009", Title: "Links Crawled", Severity: 1, Kind: "INFORMATION_GATHERED"},
		Finding{ID: "150123", Title: "set aside", Severity: 2, Kind: "VULNERABILITY", Ignored: true},
	)
	return OwnerReportInput{
		Delivery: Delivery{App: "Example Site", AppID: "101", ScanTitle: "ExampleSite Run #50",
			URL: "http://www.example.com", Finished: fin, Started: fin.Add(-75 * time.Minute),
			Duration: 75 * time.Minute, AuthLabel: "unauthenticated scan", LinksCrawled: 134,
			ScanDelta: Counts{Urgent: 1, Medium: 8, Serious: -2}, Launch: "SCHEDULED"},
		Findings: fs,
		Remedies: map[string]Remedy{
			"530636": {Diagnosis: "The plugin does not check file types.", Consequence: "Remote code execution.",
				Solution: "Upgrade the plugin to 2.9.21 or later. Then retest.", CVEs: []string{"CVE-2025-12352"},
				Category: "Information Disclosure"},
			"150123": {Diagnosis: "No HttpOnly.", Consequence: "Scripts can read it.", Solution: "Set HttpOnly.",
				Category: "Information Disclosure"},
		},
		Org:       "Example Org",
		Generated: fin.Add(12 * time.Hour),
	}
}

func TestOwnerReportShowsWhatWasScannedAndWhatIsOpen(t *testing.T) {
	out := string(RenderOwnerReport(sampleOwnerReport()))
	if p := os.Getenv("OWNER_REPORT_PREVIEW"); p != "" {
		_ = os.WriteFile(p, []byte(out), 0o600) // a look at the real renderer's output
	}
	for _, want := range []string{
		"http://www.example.com",                   // the URL scanned - the email used to lack it
		">1</b><span>Urgent", ">6</b><span>Medium", // tiles: open vulnerabilities, ignored left out
		"Worst open: Urgent.", "Fix:</b> Upgrade the plugin to 2.9.21 or later.",
		"A02 Security Misconfiguration", "A10 Mishandling of Exceptional Conditions", // every OWASP row
		"By group", "Information Disclosure",
		"3 places", "Potential", "CVSS <b>9.8</b>", "CVE <b>CVE-2025-12352</b>", "QDS <b>95</b>",
		"Security weaknesses <span class=\"n\">(2)", "HSTS header missing", "Possible DOM XSS",
		"What the scanner also recorded (1 items", "Links Crawled", // diagnostics, folded, kept
		"1 set aside in the scanner",
		"+1 Urgent, −2 Serious, +8 Medium", // worst first
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// The explanation appears once per kind, not once per place.
	if n := strings.Count(out, "Scripts can read it."); n != 1 {
		t.Errorf("an explanation appeared %d times, want once per kind", n)
	}
	// Worst first: the Urgent card before the Medium ones.
	if strings.Index(out, "530636") > strings.Index(out, "150123") {
		t.Error("cards are not worst first")
	}
}

func TestOwnerReportIsSelfContainedAndEscaped(t *testing.T) {
	in := sampleOwnerReport()
	in.Delivery.App = `Evil <script>alert(1)</script> App`
	in.Findings[0].Title = `<img src=x onerror=alert(2)>`
	in.Findings[0].Evidence.Payload = `"><script>alert(document.domain)</script>`
	out := string(RenderOwnerReport(in))

	// A live tag, not its escaped text: "&lt;img src=x onerror=...&gt;" is
	// inert and shows the reader exactly what the scanner reported.
	if regexp.MustCompile(`(?i)<(script|img|svg|iframe|object)\b|<[a-z][^>]*\son[a-z]+\s*=`).MatchString(out) {
		t.Error("scanner text reached the page as markup")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(document.domain)&lt;/script&gt;") {
		t.Error("the payload is not shown (escaped) - developers need it to reproduce the flaw")
	}
	// Nothing loads from anywhere: no src or href attribute, no stylesheet
	// link, no CSS import - checked on the ordinary report, whose text has
	// no "src=" of its own.
	clean := string(RenderOwnerReport(sampleOwnerReport()))
	if regexp.MustCompile(`(?i)<[a-z][^>]*\s(src|href)\s*=|<link\b|@import|url\(`).MatchString(clean) {
		t.Error("the report references an external resource")
	}
	if strings.Contains(out, "set-cookie: __") {
		t.Error("a cookie value survived")
	}
}

func TestOwnerReportWithNothingOpenSaysSo(t *testing.T) {
	in := sampleOwnerReport()
	in.Findings = nil
	in.Delivery.URL = ""
	out := string(RenderOwnerReport(in))
	for _, want := range []string{"No vulnerabilities are open.", "not available", ">0</b><span>Urgent"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty report lacks %q", want)
		}
	}
	if strings.Contains(out, "At a glance") {
		t.Error("charts drawn with nothing to chart")
	}
}
