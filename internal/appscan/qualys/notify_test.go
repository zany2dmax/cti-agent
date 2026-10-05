package qualys

import (
	"strings"
	"testing"
	"time"
)

// Both fixtures mirror the structure of a real Qualys WAS notification: the
// hidden preheader, the Proofpoint banner, the label block, both count tables,
// and the wrapped report links.
//
// Every application name, reference and identifier is invented. The real scan
// titles enumerate the web estate - which applications exist, which are
// scanned, and which are scanned WITHOUT authentication - and this repository
// is public. That list is a map of where to look.

// blindScan: no authentication record, and consequently "clean".
const blindScan = `
<div style="display:none">Email scan summary by Qualys Scan Title : Example Site Run #48</div>
<div id="pfptBannerabc123" style="display:block">This Message Is From an External Sender</div>
<div><p>Email scan summary by Qualys</p></div>
<div><div>Scan Title : Example Site Run #48</div>
<div>Scan Reference : was/1111111111111.22222222</div>
<div>Start Date : 10/04/2026 at 00:02:43 (GMT +0000)</div>
<div>End Date : 10/04/2026 at 03:45:01 (GMT +0000)</div>
<div>Duration : 03:42:18</div>
<div>Target : Example Homepage <br />Authentication Record : None <br /><br />Hosts Scanned : 1 <br />Active Hosts : 1 </div>
<div>Launched By : Someone(acct)</div>
<div>Scan Status : Finished : OK </div>
<div>Authentication Status : No Authentication specified</div>
<div>Scan Statistics<br />Summary of Crawling (+/-)<br /><br />Links Crawled : 252 ( +8 ) <br />
<div>Summary of Vulnerabilities (+/-)<br /><br />Severity 5 "Urgent" : 0 (=) <br />Severity 4 "Critical" : 0 (=) <br />Severity 3 "Serious" : 1 ( -1 ) <br />Severity 2 "Medium" : 2 (=) <br />Severity 1 "Minimal" : 50 (=) <br /><br />Total : 53 ( -1 ) <br /></div>
<div>Summary of Sensitive Contents (+/-)<br /><br />Severity 5 "Urgent" : 0 (=) <br />Severity 1 "Minimal" : 0 (=) <br /><br />Total : 0 (=) <br /></div>
<div>Summary of Information Gathered (+/-)<br /><br />Severity 3 "Serious" : 3 (=) <br />Severity 2 "Medium" : 9 ( +1 ) <br /><br />Total : 58 ( +1 ) <br /></div>
<div>Web Application Statistics<br />
<div>Vulnerabilities (New, Reopened, Active, Fixed, Ignored)<br /><br />Severity 5 "Urgent" : 0 ( 0 New, 0 Reopened, 0 Active, 0 Fixed, 0 Ignored) <br />Severity 4 "Critical" : 1 ( 0 New, 0 Reopened, 0 Active, 1 Fixed, 0 Ignored) <br />Severity 3 "Serious" : 16 ( 0 New, 0 Reopened, 1 Active, 15 Fixed, 0 Ignored) <br />Severity 2 "Medium" : 11 ( 0 New, 0 Reopened, 2 Active, 9 Fixed, 0 Ignored) <br />Severity 1 "Minimal" : 111 ( 0 New, 5 Reopened, 67 Active, 39 Fixed, 0 Ignored) <br />Total : 139 <br /></div>
<div>Sensitive Contents (New, Reopened, Active, Fixed, Ignored)<br /><br />Severity 5 "Urgent" : 0 ( 0 New, 0 Reopened, 0 Active, 0 Fixed, 0 Ignored) <br />Total : 0 <br /></div></div></div>
<div>If you wish to view these scan results, click here : <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/scan/25080057__;Iw!!A!B$">link</a></div>
`

// deepScan: authenticated, and finding things.
const deepScan = `
<div><div>Scan Title : Example Portal Bimonthly Run #47</div>
<div>Scan Reference : was/3333333333333.44444444</div>
<div>Start Date : 10/04/2026 at 00:02:47 (GMT +0000)</div>
<div>End Date : 10/04/2026 at 13:47:06 (GMT +0000)</div>
<div>Target : Example Portal <br />Authentication Record : example portal auth record <br /></div>
<div>Scan Status : Finished : OK </div>
<div>Authentication Status : Successful</div>
<div>Links Crawled : 67 ( +7 ) <br />
<div>Summary of Vulnerabilities (+/-)<br /><br />Severity 5 "Urgent" : 20 ( -8 ) <br />Severity 4 "Critical" : 4 ( -5 ) <br />Severity 3 "Serious" : 24 ( -5 ) <br />Severity 2 "Medium" : 8 ( -1 ) <br />Severity 1 "Minimal" : 2 (=) <br /><br />Total : 58 ( -19 ) <br /></div>
<div>Summary of Sensitive Contents (+/-)<br /><br />Severity 5 "Urgent" : 0 (=) <br /><br />Total : 0 (=) <br /></div>
<div>Web Application Statistics<br />
<div>Vulnerabilities (New, Reopened, Active, Fixed, Ignored)<br /><br />Severity 5 "Urgent" : 270 ( 0 New, 0 Reopened, 23 Active, 247 Fixed, 0 Ignored) <br />Severity 4 "Critical" : 100 ( 2 New, 0 Reopened, 2 Active, 96 Fixed, 0 Ignored) <br />Severity 3 "Serious" : 771 ( 1 New, 4 Reopened, 21 Active, 745 Fixed, 0 Ignored) <br />Severity 2 "Medium" : 102 ( 0 New, 0 Reopened, 8 Active, 94 Fixed, 0 Ignored) <br />Severity 1 "Minimal" : 27 ( 0 New, 0 Reopened, 2 Active, 25 Fixed, 0 Ignored) <br />Total : 1270 <br /></div>
<div>Sensitive Contents (New, Reopened, Active, Fixed, Ignored)<br /><br />Severity 5 "Urgent" : 0 ( 0 New, 0 Reopened, 0 Active, 0 Fixed, 0 Ignored) <br />Total : 0 <br /></div></div></div>
<div>If you wish to view these scan results, click here : <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/scan/25080022__;Iw!!A!B$">link</a></div>
`

func TestRecognisesOnlyQualysNotifications(t *testing.T) {
	var p Provider
	if !p.Recognises("qualys@qualys.net", "Qualys: Web Application Vulnerability Scan Results - X Run #1") {
		t.Error("did not recognise a real notification")
	}
	// Sender AND subject. A colleague forwarding one of these in has a body
	// this parser cannot read, wrapped in their commentary.
	if p.Recognises("jeff@example.com", "FW: Qualys: Web Application Vulnerability Scan Results") {
		t.Error("recognised a forward from a person")
	}
	if p.Recognises("qualys@qualys.net", "Qualys: Your subscription is expiring") {
		t.Error("recognised an unrelated Qualys email")
	}
}

func TestTheAuthenticatedScanParsesCompletely(t *testing.T) {
	r, problems := Provider{}.Parse(deepScan)

	if len(problems) != 0 {
		t.Errorf("problems on a well-formed notification: %v", problems)
	}
	if r.App != "Example Portal" {
		t.Errorf("App = %q - the run suffix should be stripped", r.App)
	}
	if r.ScanTitle != "Example Portal Bimonthly Run #47" {
		t.Errorf("ScanTitle = %q", r.ScanTitle)
	}
	if r.Reference != "was/3333333333333.44444444" {
		t.Errorf("Reference = %q", r.Reference)
	}
	if !r.Complete {
		t.Errorf("Complete = false for %q", r.Status)
	}
	if !r.Auth.Authenticated() {
		t.Errorf("Auth = %+v, want authenticated", r.Auth)
	}
	if r.LinksCrawled != 67 {
		t.Errorf("LinksCrawled = %d", r.LinksCrawled)
	}
	want := time.Date(2026, 10, 4, 13, 47, 6, 0, time.UTC)
	if !r.Finished.Equal(want) {
		t.Errorf("Finished = %v, want %v", r.Finished, want)
	}
}

func TestTheTwoCountSystemsAreNotConflated(t *testing.T) {
	// The whole reason they are separate types. This scan FOUND 20 Urgent.
	// The application has 270 Urgent on record, of which 247 are Fixed and
	// only 23 are Active. Reporting 270 as current exposure would raise a
	// false alarm an order of magnitude too large; reporting 20 as the
	// backlog understates it differently.
	r, _ := Provider{}.Parse(deepScan)

	if r.ScanCounts.Urgent != 20 {
		t.Errorf("ScanCounts.Urgent = %d, want 20 (what this scan found)", r.ScanCounts.Urgent)
	}
	if r.AppState.Total.Urgent != 270 {
		t.Errorf("AppState.Total.Urgent = %d, want 270 (lifecycle)", r.AppState.Total.Urgent)
	}
	if r.AppState.Active.Urgent != 23 {
		t.Errorf("AppState.Active.Urgent = %d, want 23 (actually open)", r.AppState.Active.Urgent)
	}
	if r.AppState.Fixed.Urgent != 247 {
		t.Errorf("AppState.Fixed.Urgent = %d, want 247", r.AppState.Fixed.Urgent)
	}
	if r.AppState.New.Crit != 2 || r.AppState.Reopened.Serious != 4 {
		t.Errorf("New.Crit = %d (want 2), Reopened.Serious = %d (want 4)",
			r.AppState.New.Crit, r.AppState.Reopened.Serious)
	}
}

func TestTheDeltasQualysComputesAreKept(t *testing.T) {
	// Trend for free, with no state of our own to drift.
	r, _ := Provider{}.Parse(deepScan)
	if r.ScanDelta.Urgent != -8 || r.ScanDelta.Crit != -5 {
		t.Errorf("ScanDelta = %+v, want Urgent -8 and Crit -5", r.ScanDelta)
	}
	// "(=)" means no change, and must not be read as zero findings.
	if r.ScanDelta.Minimal != 0 || r.ScanCounts.Minimal != 2 {
		t.Errorf("'(=)' was misread: delta %d, count %d",
			r.ScanDelta.Minimal, r.ScanCounts.Minimal)
	}
}

func TestTheSectionBoundIsRespected(t *testing.T) {
	// Three tables in this email open with a "Severity 5" line. Without
	// bounding each section to its own heading the parser reads whichever
	// comes first and silently returns the Sensitive Contents figures, which
	// are almost always zero - a clean-looking wrong answer.
	r, _ := Provider{}.Parse(blindScan)

	if r.ScanCounts.Serious != 1 || r.ScanCounts.Minimal != 50 {
		t.Errorf("ScanCounts = %+v - looks like another section was read", r.ScanCounts)
	}
	if r.AppState.Total.Minimal != 111 {
		t.Errorf("AppState.Total.Minimal = %d, want 111", r.AppState.Total.Minimal)
	}
}

func TestAnUnauthenticatedScanIsLabelledNotFaulted(t *testing.T) {
	// Observed on two real scans the same night: the unauthenticated one
	// crawled 252 links and reported zero Urgent and zero Critical; the
	// authenticated one crawled 67 and found twenty Urgent. The first
	// application is not safer - the two scans covered different surfaces,
	// and a reader looking at a zero cannot tell which kind produced it.
	//
	// SO THE SCAN CARRIES A LABEL. What it must NOT carry is a defect. The
	// first version of this package returned true from Blind() here and true
	// from Attention(), which put three public sites with no login at the top
	// of the weekly report under a heading reading COVERAGE GAPS - a standing
	// complaint, with no missing credential behind it and nothing anybody
	// could do. A permanent alarm is read as no alarm.
	r, _ := Provider{}.Parse(blindScan)

	if r.Auth.Record != "" {
		t.Errorf("Auth.Record = %q - Qualys's literal \"None\" must read as absent", r.Auth.Record)
	}
	if r.Auth.Configured() {
		t.Error("Configured() is true with no credential set")
	}
	if r.Auth.Authenticated() {
		t.Error("an unauthenticated scan reported itself authenticated")
	}
	if r.Auth.Failed() {
		t.Error("no credential was configured, so nothing failed - Failed() " +
			"must mean a credential that did not work")
	}
	if got := r.Auth.Label(); got != "unauthenticated scan" {
		t.Errorf("Label() = %q", got)
	}
	if r.Fault() {
		t.Error("an unauthenticated scan was treated as a scanner fault")
	}
	if r.Attention() {
		t.Error("a complete scan of a site with no login demanded attention " +
			"every week with nothing to act on")
	}
}

func TestAConfiguredButFailedLoginIsAFault(t *testing.T) {
	// The nastiest case, and the one that IS a fault: a record is configured,
	// so the setup looks right to anyone reviewing it in Qualys, and the scan
	// nonetheless only saw the public surface. This week's numbers therefore
	// are not comparable with last week's, and nobody writing application code
	// can fix it - which is why cti-appscan alerts the operator on exactly
	// this predicate.
	body := strings.Replace(deepScan,
		"Authentication Status : Successful",
		"Authentication Status : Failed", 1)
	r, _ := Provider{}.Parse(body)

	if r.Auth.Record == "" {
		t.Fatal("the fixture should still have a record configured")
	}
	if !r.Auth.Configured() {
		t.Error("a scan with a named credential reported none configured")
	}
	if r.Auth.Authenticated() {
		t.Error("a failed login counted as authenticated")
	}
	if !r.Auth.Failed() {
		t.Error("a configured credential that did not authenticate is a failure")
	}
	if !r.Fault() {
		t.Error("a failed authentication is a scanner fault")
	}
	if !r.Attention() {
		t.Error("a failed authentication did not warrant attention")
	}
}

func TestAnIncompleteScanIsNotPresentedAsAResult(t *testing.T) {
	// Counts from a cancelled or time-limited scan describe a partial crawl.
	for _, status := range []string{
		"Scan Status : Canceled",
		"Scan Status : Finished : Time Limit Exceeded",
		"Scan Status : Error",
	} {
		body := strings.Replace(deepScan, "Scan Status : Finished : OK ", status+" ", 1)
		r, _ := Provider{}.Parse(body)
		if r.Complete {
			t.Errorf("%q reported Complete", status)
		}
		if !r.Attention() {
			t.Errorf("%q did not warrant attention", status)
		}
	}
}

func TestAHealthyAuthenticatedScanWithNoChangesIsQuiet(t *testing.T) {
	// The other direction. If everything warrants attention, nothing does.
	body := strings.Replace(deepScan,
		`Severity 4 "Critical" : 100 ( 2 New, 0 Reopened, 2 Active, 96 Fixed, 0 Ignored)`,
		`Severity 4 "Critical" : 100 ( 0 New, 0 Reopened, 2 Active, 98 Fixed, 0 Ignored)`, 1)
	body = strings.Replace(body,
		`Severity 3 "Serious" : 771 ( 1 New, 4 Reopened, 21 Active, 745 Fixed, 0 Ignored)`,
		`Severity 3 "Serious" : 771 ( 0 New, 0 Reopened, 21 Active, 750 Fixed, 0 Ignored)`, 1)
	r, _ := Provider{}.Parse(body)

	if r.Attention() {
		t.Errorf("a complete authenticated scan with nothing new asked for "+
			"attention: New=%+v Reopened=%+v", r.AppState.New, r.AppState.Reopened)
	}
}

func TestTheReportLinkIsUnwrappedAndVerified(t *testing.T) {
	r, _ := Provider{}.Parse(blindScan)
	if !strings.HasPrefix(r.ReportURL, "https://qualysguard.qg3.apps.qualys.com/") {
		t.Errorf("ReportURL = %q (problem: %q)", r.ReportURL, r.LinkProblem)
	}
}

func TestALinkThatIsNotQualysIsAFindingNotSilence(t *testing.T) {
	body := strings.Replace(blindScan,
		"https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/scan/25080057__;Iw!!A!B$",
		"https://qualysguard.qg3.apps.qualys.com.evil.example/x", 1)
	r, problems := Provider{}.Parse(body)

	if r.ReportURL != "" {
		t.Errorf("a lookalike host was accepted: %q", r.ReportURL)
	}
	if r.LinkProblem == "" {
		t.Error("the rejected link left no explanation")
	}
	if !contains(problems, "did not resolve") {
		t.Errorf("problems do not mention the link: %v", problems)
	}
}

func TestASeverityLineMissedByTheParserIsReported(t *testing.T) {
	// Qualys states its own total. When the parsed lines do not sum to it,
	// a line was missed - which would otherwise be a quietly smaller number.
	body := strings.Replace(blindScan, `Severity 1 "Minimal" : 50 (=) <br />`, "", 1)
	_, problems := Provider{}.Parse(body)

	if !contains(problems, "a severity line was missed") {
		t.Errorf("a dropped severity line was not caught: %v", problems)
	}
}

func TestAnUnrecognisedTemplateProducesProblemsNotAThinnerReport(t *testing.T) {
	r, problems := Provider{}.Parse("<html><body><p>Something else entirely</p></body></html>")

	if r.ScanTitle != "" || r.Reference != "" {
		t.Errorf("unrecognised HTML produced fields: %+v", r)
	}
	if len(problems) < 3 {
		t.Errorf("only %d problems for an unrecognised template: %v", len(problems), problems)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
