package qualys

import (
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// The fields below the counts: identity, launch, baseline and reachability.
// Fixtures follow the real template line for line; every name, reference and
// id is invented, for the reason given at the top of notify_test.go.

// trendScan is a scheduled re-scan with a baseline, sensitive content, and the
// application table immediately after "information gathered" - the layout
// that would let the application table's lines leak into InfoCounts.
const trendScan = `
<div style="display:none">Email scan summary by Qualys Scan Title : Example Shop Run #40</div>
<div id="pfptBannerabc123" style="display:block">This Message Is From an External Sender</div>
<div><p>Email scan summary by Qualys</p></div>
<div><p></p><div>Scan Title : Example Shop Run #40</div>
<div>Scan Reference : was/5555555555555.66666666</div><p></p>
<div>Start Date : 11/02/2026 at 01:29:08 (GMT +0000)</div>
<div>End Date : 11/02/2026 at 13:51:36 (GMT +0000)</div>
<div>Duration : 12:22:28</div><p></p>
<div>Target : Example Shop <br />Authentication Record : None <br /><br />Hosts Scanned : 1 <br />Active Hosts : 1 </div>
<div>Option Profile : Initial WAS Options</div>
<div>Launched By : Team Account(acct1)</div>
<div>Company : Example Co</div>
<div>Launch Type : Scheduled</div>
<div>Scan Status : Finished : OK </div>
<div>Authentication Status : No Authentication specified</div>
<div>Next Action : N/A</div><hr />
<div><div>Scan Statistics<br />================================================<br />
<div>Summary of Crawling (+/-)<br /><br />Links Crawled : 459 ( +39 ) <br /><br /><br /></div>
<div>Summary of Vulnerabilities (+/-)<br /><br />Severity 5 "Urgent" : 0 (=) <br />Severity 4 "Critical" : 0 (=) <br />Severity 3 "Serious" : 13 ( -1 ) <br />Severity 2 "Medium" : 35 (=) <br />Severity 1 "Minimal" : 56 ( -1 ) <br /><br />Total : 104 ( -2 ) <br /><br /><br /></div>
<div>Summary of Sensitive Contents (+/-)<br /><br />Severity 5 "Urgent" : 0 (=) <br />Severity 4 "Critical" : 0 (=) <br />Severity 3 "Serious" : 2 ( +2 ) <br />Severity 2 "Medium" : 0 (=) <br />Severity 1 "Minimal" : 0 (=) <br /><br />Total : 2 ( +2 ) <br /><br /><br /></div>
<div>Summary of Information Gathered (+/-)<br /><br />Severity 5 "Urgent" : 0 (=) <br />Severity 4 "Critical" : 0 (=) <br />Severity 3 "Serious" : 4 (=) <br />Severity 2 "Medium" : 9 (=) <br />Severity 1 "Minimal" : 57 ( -1 ) <br /><br />Total : 70 ( -1 ) <br /><br /><br /></div>
<div>Comparison has been made with scan launched on 11/01/2026 at 01:28:17 (GMT +0000), reference: was/5555555555554.66666665 </div>
<div><br /><div>Legend<br /><hr /><br />(+/-) Trend with last scan<br /><br /></div>
<div>Web Application Statistics<br />================================================<br />
<div>Vulnerabilities (New, Reopened, Active, Fixed, Ignored)<br /><br />Severity 5 "Urgent" : 1 ( 0 New, 0 Reopened, 0 Active, 1 Fixed, 0 Ignored) <br />Severity 4 "Critical" : 0 ( 0 New, 0 Reopened, 0 Active, 0 Fixed, 0 Ignored) <br />Severity 3 "Serious" : 25 ( 0 New, 1 Reopened, 12 Active, 12 Fixed, 0 Ignored) <br />Severity 2 "Medium" : 41 ( 0 New, 0 Reopened, 35 Active, 6 Fixed, 0 Ignored) <br />Severity 1 "Minimal" : 286 ( 3 New, 2 Reopened, 101 Active, 180 Fixed, 0 Ignored) <br />Total : 353 <br /><br /></div>
<div>Sensitive Contents (New, Reopened, Active, Fixed, Ignored)<br /><br />Severity 5 "Urgent" : 0 ( 0 New, 0 Reopened, 0 Active, 0 Fixed, 0 Ignored) <br />Total : 0 <br /><br /></div></div></div></div>
<div>If you wish to view these scan results, click here : <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/scan/25000001__;Iw!!A!B$">link</a></div>
<div>If you wish to view application status after this scan, click here : <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/webapp/900000001__;Iw!!A!B$">link</a></div>
</div>
`

// firstRun is a brand-new application's first scan, run by hand: no deltas,
// no comparison line, no application table.
const firstRun = `
<div><p>Email scan summary by Qualys</p></div>
<div><div>Scan Title : Nov 1, 2026</div>
<div>Scan Reference : was/7777777777777.88888888</div>
<div>Start Date : 11/01/2026 at 18:51:58 (GMT +0000)</div>
<div>End Date : 11/01/2026 at 20:28:50 (GMT +0000)</div>
<div>Duration : 01:36:52</div>
<div>Target : Example Academy <br />Authentication Record : Example Academy Auth <br /><br />Hosts Scanned : 1 <br />Active Hosts : 1 </div>
<div>Launched By : Some Person(acct2)</div>
<div>Launch Type : Manual</div>
<div>Scan Status : Finished : OK </div>
<div>Authentication Status : Successful</div>
<div>Scan Statistics<br /><div>Summary of Crawling <br /><br />Links Crawled : 77 <br /><br /></div>
<div>Summary of Vulnerabilities <br /><br />Severity 5 "Urgent" : 0 <br />Severity 4 "Critical" : 0 <br />Severity 3 "Serious" : 6 <br />Severity 2 "Medium" : 2 <br />Severity 1 "Minimal" : 13 <br /><br />Total : 21 <br /><br /></div>
<div>Summary of Sensitive Contents <br /><br />Severity 5 "Urgent" : 0 <br />Severity 1 "Minimal" : 0 <br /><br />Total : 0 <br /><br /></div>
<div>Summary of Information Gathered <br /><br />Severity 3 "Serious" : 1 <br />Severity 2 "Medium" : 6 <br />Severity 1 "Minimal" : 46 <br /><br />Total : 53 <br /><br /></div>
<div><div>No trends are available as no previous scan exist in your subscription for this web application and authentication record. </div></div></div>
<div>If you wish to view these scan results, click here : <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/scan/25000002__;Iw!!A!B$">link</a></div>
<div>If you wish to view application status after this scan, click here : <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/webapp/900000002__;Iw!!A!B$">link</a></div>
`

func TestTheFieldsAroundTheCountsParse(t *testing.T) {
	r, problems := Provider{}.Parse(trendScan)
	if len(problems) != 0 {
		t.Fatalf("problems on a well-formed notification: %v", problems)
	}
	if r.NoticeAppID != "900000001" {
		t.Errorf("NoticeAppID = %q, want it from the application-status link", r.NoticeAppID)
	}
	if r.AppID != "" {
		t.Errorf("AppID = %q - an id from mail must never fill the lookup key", r.AppID)
	}
	if r.HostsScanned != 1 || r.ActiveHosts != 1 {
		t.Errorf("hosts = %d scanned, %d active", r.HostsScanned, r.ActiveHosts)
	}
	if r.Launch != "Scheduled" || r.LaunchedBy != "Team Account(acct1)" {
		t.Errorf("Launch = %q, LaunchedBy = %q", r.Launch, r.LaunchedBy)
	}
	if r.Profile != "Initial WAS Options" {
		t.Errorf("Profile = %q", r.Profile)
	}
	if want := 12*time.Hour + 22*time.Minute + 28*time.Second; r.Duration != want {
		t.Errorf("Duration = %v, want %v", r.Duration, want)
	}
	if r.LinksCrawled != 459 || r.LinksDelta != 39 {
		t.Errorf("links = %d (%+d)", r.LinksCrawled, r.LinksDelta)
	}
	if r.FirstScan || r.PreviousRef != "was/5555555555554.66666665" {
		t.Errorf("FirstScan = %v, PreviousRef = %q", r.FirstScan, r.PreviousRef)
	}
	if r.SensitiveCounts.Serious != 2 || r.SensitiveCounts.Total() != 2 {
		t.Errorf("SensitiveCounts = %+v", r.SensitiveCounts)
	}
	// 4+9+57. Unbounded, the application table's "Severity 5 ... : 1" and
	// friends would overwrite these with 1, 0, 25, 41, 286.
	if r.InfoCounts.Total() != 70 || r.InfoCounts.Urgent != 0 {
		t.Errorf("InfoCounts = %+v - the application table leaked in", r.InfoCounts)
	}
	if r.ScanCounts.Total() != 104 {
		t.Errorf("ScanCounts total = %d - the new sections disturbed the old one", r.ScanCounts.Total())
	}
}

func TestAFirstScanSaysItHasNoBaseline(t *testing.T) {
	r, problems := Provider{}.Parse(firstRun)
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if !r.FirstScan || r.PreviousRef != "" {
		t.Errorf("FirstScan = %v, PreviousRef = %q", r.FirstScan, r.PreviousRef)
	}
	if r.Launch != "Manual" {
		t.Errorf("Launch = %q", r.Launch)
	}
	if r.LinksDelta != 0 {
		t.Errorf("LinksDelta = %d on a scan with no trend", r.LinksDelta)
	}
	if r.NoticeAppID != "900000002" {
		t.Errorf("NoticeAppID = %q", r.NoticeAppID)
	}
	if r.InfoCounts.Total() != 53 {
		t.Errorf("InfoCounts = %+v", r.InfoCounts)
	}
}

func TestAScanWithNoTemplateLinesForTheNewFieldsIsNotFirst(t *testing.T) {
	// The older fixtures carry neither a comparison line nor "No trends".
	// That is "unknown", and must not be read as a first scan.
	r, _ := Provider{}.Parse(deepScan)
	if r.FirstScan {
		t.Error("FirstScan set with no evidence for it")
	}
}

func TestAnUnansweredHostIsUnreachable(t *testing.T) {
	body := strings.Replace(trendScan, "Active Hosts : 1", "Active Hosts : 0", 1)
	r, _ := Provider{}.Parse(body)
	if !r.Unreachable() || !r.Fault() {
		t.Errorf("Unreachable = %v, Fault = %v with 1 scanned and 0 active",
			r.Unreachable(), r.Fault())
	}
	ok, _ := Provider{}.Parse(trendScan)
	if ok.Unreachable() {
		t.Error("Unreachable on a scan whose host answered")
	}
}

func TestAStatusLinkToAnotherHostIsAProblemNotAnID(t *testing.T) {
	body := strings.Replace(trendScan,
		"https://qualysguard.qg3.apps.qualys.com/was/*/reports/online-reports/email-report/webapp/900000001",
		"https://qualysguard.example.net/was/*/reports/online-reports/email-report/webapp/900000009", 1)
	r, problems := Provider{}.Parse(body)
	if r.NoticeAppID != "" {
		t.Errorf("NoticeAppID = %q taken from an unverified link", r.NoticeAppID)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "application status link") {
		t.Errorf("problems = %v", problems)
	}
}

func TestLookalikesAreTheVendorSubjectFromSomebodyElse(t *testing.T) {
	p := Provider{}
	subj := "Qualys: Web Application Vulnerability Scan Results - Example Shop Run #40"
	for _, c := range []struct {
		sender, subject string
		want            bool
		why             string
	}{
		{"team@example.com", subj, true, "the mailbox's own address - the real case"},
		{"Qualys <qualys@qualys.com.attacker.example>", subj, true, "a lookalike domain"},
		{"qualys@qualys.net", subj, false, "the real sender is Recognised, not a lookalike"},
		{"jeff@example.com", "FW: " + subj, false, "a person forwarding one needs a human, not a warning"},
		{"team@example.com", "Qualys: Scheduled Web Application Vulnerability Scan Notification",
			false, "a different notice"},
	} {
		if got := p.Lookalike(c.sender, c.subject); got != c.want {
			t.Errorf("Lookalike(%q, %q) = %v: %s", c.sender, c.subject, got, c.why)
		}
	}
}

func TestReconcileReportsANoticeWhoseAppIDDisagrees(t *testing.T) {
	r, _ := Provider{}.Parse(trendScan)
	list := []Scan{{ID: 25000001, Reference: r.Reference, Type: "VULNERABILITY",
		Mode: "SCHEDULED", WebAppID: "900000777", WebAppName: "Example Shop",
		Status: "FINISHED"}}
	out, rec := Reconcile([]appscan.ScanResult{r}, list, time.Time{}, "")
	if len(rec.IDMismatch) != 1 || rec.IDMismatch[0] != r.Reference {
		t.Errorf("IDMismatch = %v", rec.IDMismatch)
	}
	if out[0].AppID != "900000777" {
		t.Errorf("AppID = %q - the scan list's id is the one kept", out[0].AppID)
	}

	list[0].WebAppID = "900000001"
	if _, rec := Reconcile([]appscan.ScanResult{r}, list, time.Time{}, ""); len(rec.IDMismatch) != 0 {
		t.Errorf("IDMismatch = %v when the ids agree", rec.IDMismatch)
	}
}
