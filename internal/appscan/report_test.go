package appscan

import (
	"strings"
	"testing"
	"time"
)

func weekEnding() time.Time { return time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC) }

// publicScan mirrors a real unauthenticated scan of a site with NO LOGIN: a
// wide crawl that found little, because there is little behind the front page.
//
// Named publicScan, not blindScan. The old name carried the assumption this
// package had to unlearn - that a scan which did not authenticate had been
// prevented from seeing something.
func publicScan() ScanResult {
	return ScanResult{
		Provider: "qualys-was", App: "Example Site", Complete: true,
		Status: "Finished : OK", LinksCrawled: 252,
		Auth:       Auth{Record: "", Status: "No Authentication specified"},
		ScanCounts: Counts{Serious: 1, Medium: 2, Minimal: 50},
		AppState: Lifecycle{
			Total:    Counts{Crit: 1, Serious: 16, Medium: 11, Minimal: 111},
			Active:   Counts{Serious: 1, Medium: 2, Minimal: 67},
			Reopened: Counts{Minimal: 5},
			Fixed:    Counts{Crit: 1, Serious: 15, Medium: 9, Minimal: 39},
		},
	}
}

// deepScan mirrors the real authenticated scan: a narrow crawl that found a
// great deal.
func deepScan() ScanResult {
	return ScanResult{
		Provider: "qualys-was", App: "Example Portal", Complete: true,
		Status: "Finished : OK", LinksCrawled: 67,
		Auth:       Auth{Record: "portal auth record", Status: "Successful"},
		ScanCounts: Counts{Urgent: 20, Crit: 4, Serious: 24, Medium: 8, Minimal: 2},
		AppState: Lifecycle{
			Total:    Counts{Urgent: 270, Crit: 100, Serious: 771, Medium: 102, Minimal: 27},
			Active:   Counts{Urgent: 23, Crit: 2, Serious: 21, Medium: 8, Minimal: 2},
			New:      Counts{Crit: 2, Serious: 1},
			Reopened: Counts{Serious: 4},
			Fixed:    Counts{Urgent: 247, Crit: 96, Serious: 745, Medium: 94, Minimal: 25},
		},
		ReportURL: "https://qualysguard.qg3.apps.qualys.com/was/#/reports/x",
		Findings: []Finding{
			{ID: "150084", Title: "Reflected Cross-Site Scripting", Severity: 5,
				URL: "https://portal.example/search", Param: "q", Status: "NEW"},
			{ID: "150003", Title: "SQL Injection", Severity: 4,
				URL: "https://portal.example/report", Param: "id", Status: "NEW"},
			{ID: "150124", Title: "Cookie Without Secure Flag", Severity: 3,
				URL: "https://portal.example/login", Status: "REOPENED"},
			{ID: "150999", Title: "Old news", Severity: 5,
				URL: "https://portal.example/x", Status: "ACTIVE"},
		},
	}
}

// failedLogin is deepScan's application on a week the credential broke.
func failedLogin() ScanResult {
	s := deepScan()
	s.Auth.Status = "Failed"
	return s
}

func render(t *testing.T, scans ...ScanResult) Block {
	t.Helper()
	return Render(scans, weekEnding())
}

// ─── unauthenticated is a label, not a defect ───────────────────────────────

func TestAPublicSiteWithNoLoginIsNotACoverageGap(t *testing.T) {
	// THE BUG THIS FILE EXISTS TO PREVENT A SECOND TIME.
	//
	// The first real send of this report named three applications under a
	// heading reading COVERAGE GAPS. All three are public sites with no login:
	// no credential is missing, nothing is misconfigured, and there is nothing
	// for the audience of this mail to do. The operator's words: "those sites
	// have no login to them, hence there is no missing authentication record."
	b := render(t, deepScan(), publicScan())

	for _, forbidden := range []string{
		"COVERAGE GAP", "Coverage gap", "coverage gap",
		"no authentication record configured", "not evidence",
	} {
		if strings.Contains(b.Text, forbidden) {
			t.Errorf("the report still frames an unauthenticated scan as a "+
				"defect: found %q\n%s", forbidden, b.Text)
		}
	}
	if strings.Contains(b.Text, "SCANNER FAULTS") {
		t.Errorf("a week with nothing broken raised a fault section:\n%s", b.Text)
	}
}

func TestAnUnauthenticatedScanDoesNotDemandAttention(t *testing.T) {
	// Attention() used to return true for every scan that had not
	// authenticated, which put these at the top of the report every single
	// week with nothing actionable in them. A permanent alarm is read as no
	// alarm, and it trains people to skip the top of the page.
	if publicScan().Attention() {
		t.Error("a complete scan of a site with no login asked for attention")
	}
	if publicScan().Fault() {
		t.Error("a site with no login was reported as a scanner fault")
	}
}

func TestAnUnauthenticatedScanDoesNotOutrankRealFindings(t *testing.T) {
	// The consequence of the above, in the ordering. The application with 23
	// Urgent open belongs above the one with one Serious.
	b := render(t, publicScan(), deepScan())
	open := b.Text[strings.Index(b.Text, "OPEN NOW"):]
	portal := strings.Index(open, "Example Portal")
	site := strings.Index(open, "Example Site")
	if portal < 0 || site < 0 {
		t.Fatalf("an application is missing from OPEN NOW:\n%s", open)
	}
	if portal > site {
		t.Errorf("the application with 23 Urgent sorted below a public site "+
			"with one Serious:\n%s", open)
	}
}

func TestEveryCountSaysWhichSurfaceItDescribes(t *testing.T) {
	// The part of the old design worth keeping. A zero from a scan that only
	// saw the public pages means something different from a zero from a scan
	// that logged in, and the number alone cannot say which.
	b := render(t, deepScan(), publicScan())
	open := b.Text[strings.Index(b.Text, "OPEN NOW"):]
	open = open[:strings.Index(open, "CHANGED THIS WEEK")]

	// The BRACKETED form. "authenticated scan" is a substring of
	// "unauthenticated scan", so the loose check passed either way round.
	for app, want := range map[string]string{
		"Example Portal": "[authenticated scan]",
		"Example Site":   "[unauthenticated scan]",
	} {
		found := false
		for _, line := range strings.Split(open, "\n") {
			if strings.Contains(line, app) {
				found = true
				if !strings.Contains(line, want) {
					t.Errorf("%s: line does not carry %q: %q", app, want, line)
				}
			}
		}
		if !found {
			t.Errorf("no OPEN NOW line for %s", app)
		}
	}
}

func TestTheScopeNoteExplainsWithoutAccusing(t *testing.T) {
	b := render(t, deepScan(), publicScan())
	if !strings.Contains(b.Text, "no login that is the whole application") {
		t.Errorf("the report does not explain what an unauthenticated scan "+
			"covers:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "labelled rather than flagged") {
		t.Error("the report does not say the label is a property of the " +
			"application rather than a finding")
	}
}

// ─── a failed login IS a fault, and goes to the operator ────────────────────

func TestAFailedLoginIsALoudFault(t *testing.T) {
	// The nastiest case and the one that is a real defect: a credential is
	// configured, so the setup looks right in Qualys, and it did not work.
	b := render(t, failedLogin(), publicScan())

	if !strings.Contains(b.Text, "SCANNER FAULTS") {
		t.Fatalf("a failed credential did not raise a fault section:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "authentication failed") {
		t.Error("the fault does not say what failed")
	}
	if !strings.Contains(b.Text, `Credential "portal auth record"`) {
		t.Error("the fault does not name the credential somebody has to go and fix")
	}
	if !strings.Contains(b.Text, "fleet operator has been alerted") {
		t.Error("the report does not say the operator was told - the App Dev " +
			"audience cannot fix a scanner credential and should not be left " +
			"thinking it is their item")
	}
}

func TestAFailedLoginDoesNotEraseTheOpenBacklog(t *testing.T) {
	// Found by rendering it: the first implementation partitioned faults and
	// counted scans as mutually exclusive, so the week this application's login
	// broke it vanished from OPEN NOW and the severity tiles read zero. A
	// report saying "0 Urgent" because the scanner had a bad password is worse
	// than no report.
	b := render(t, failedLogin())

	if !strings.Contains(b.Text, "23 Urgent") {
		t.Errorf("23 open Urgent findings disappeared because the scan could "+
			"not log in:\n%s", b.Text)
	}
	open := b.Text[strings.Index(b.Text, "OPEN NOW"):]
	if !strings.Contains(open, "Example Portal") {
		t.Errorf("the application is missing from OPEN NOW:\n%s", open)
	}
	if !strings.Contains(open, "authentication FAILED") {
		t.Errorf("its counts are not marked as coming from a scan whose login "+
			"failed:\n%s", open)
	}
}

func TestAFailedLoginIsNotCountedAmongTheOrdinaryUnauthenticatedScans(t *testing.T) {
	// Two public sites plus one broken login. The scope note describes the two;
	// folding the third in would make a fault look like one of the normal ones.
	second := publicScan()
	second.App = "Example Careers"
	b := render(t, failedLogin(), publicScan(), second)

	if !strings.Contains(b.Text, "2 scan(s) above ran unauthenticated") {
		t.Errorf("the scope note counted the failed login as an ordinary "+
			"unauthenticated scan:\n%s", b.Text)
	}
}

// ─── the subject line ───────────────────────────────────────────────────────

func TestTheSubjectNamesTheFleet(t *testing.T) {
	// It used to read "[AppSec] Week of Oct 4: ...", which nowhere says where
	// the mail came from. Every other message the fleet sends opens with CTI.
	for _, b := range []Block{
		render(t, deepScan()),
		render(t, failedLogin()),
		render(t),
	} {
		if !strings.Contains(b.Subject, "CTI Fleet") {
			t.Errorf("Subject = %q - it does not say it is from the CTI fleet",
				b.Subject)
		}
	}
}

func TestTheSubjectLeadsWithTheFaultNotTheCount(t *testing.T) {
	// "23 Urgent open" is a known quantity somebody is working through. "The
	// scanner could not log in" means this week's numbers are not comparable
	// with last week's and nobody has looked at why.
	b := render(t, failedLogin(), publicScan())
	if !strings.Contains(b.Subject, "AUTH FAILED") {
		t.Errorf("Subject = %q", b.Subject)
	}

	// With nothing broken, the count leads - and an unauthenticated scan is
	// not "something broken".
	b2 := render(t, deepScan(), publicScan())
	if !strings.Contains(b2.Subject, "23 Urgent") {
		t.Errorf("Subject = %q, want the open Urgent count", b2.Subject)
	}
	if strings.Contains(b2.Subject, "without authentication") {
		t.Errorf("Subject = %q - a public site with no login is not subject "+
			"line news every week", b2.Subject)
	}
}

// ─── the house style ────────────────────────────────────────────────────────

func TestTheHtmlMatchesTheDailyBriefsLayout(t *testing.T) {
	// The operator's first note on the real email: "it should mimic the daily
	// and fleet message colors and layout". These are the daily's own values,
	// from fleet-kit/fleet/lanes/brief.py - the page background, the navy
	// header band, the 640px card and the Sev5 red.
	b := render(t, deepScan(), publicScan())
	for _, want := range []string{
		"<!DOCTYPE html>",
		"background:#eef1f5", // page behind the card
		"background:#12203a", // header band
		"max-width:640px",    // the card
		"#b3001b",            // the palette's top-severity red
		"-apple-system,Segoe UI",
	} {
		if !strings.Contains(b.HTML, want) {
			t.Errorf("the HTML does not carry %q from the daily's style", want)
		}
	}
	if !strings.Contains(b.HTML, "CTI AppSec Weekly") {
		t.Error("the header band does not name the report")
	}
}

func TestTheOrgNameComesFromTheEnvironment(t *testing.T) {
	t.Setenv("FLEET_ORG", "Example Industries")
	if b := render(t, deepScan()); !strings.Contains(b.HTML, "Example Industries") {
		t.Error("FLEET_ORG did not reach the header band")
	}
}

func TestTheScaleIsStatedEveryTime(t *testing.T) {
	// Qualys severity 5 is a claim about one HTTP response; the fleet's Sev5
	// means exploited in the wild and confirmed present. The palette is shared
	// so the mail is recognisable; the words must not be.
	// No apostrophe in the needle: html.EscapeString renders "fleet's" as
	// "fleet&#39;s", so a needle containing one passes on the text and fails
	// on the HTML for a reason that has nothing to do with the behaviour.
	b := render(t, deepScan())
	for _, s := range []string{b.Text, b.HTML} {
		if !strings.Contains(s, "Sev5-Sev1 bands") {
			t.Error("the report does not distinguish Qualys severities from " +
				"the fleet's Sev bands")
		}
	}
}

// ─── the two count systems ──────────────────────────────────────────────────

func TestOpenNowReportsActiveNotLifecycleTotals(t *testing.T) {
	// The application carries 270 "Urgent" on record, of which 247 are Fixed.
	// Leading with 270 would be a false alarm an order of magnitude too large.
	b := render(t, deepScan())
	if !strings.Contains(b.Text, "23 Urgent") {
		t.Errorf("Active Urgent not reported:\n%s", b.Text)
	}
	if strings.Contains(b.Text, "270") {
		t.Errorf("a lifecycle total reached the report:\n%s", b.Text)
	}
}

func TestLowSeveritiesAreCountedNotLedWith(t *testing.T) {
	// 67 Minimal dominated the line in the first draft, pushing the one
	// number that matters off to the right. They are a tail now - present,
	// because silence and zero must not look the same, but not prominent.
	b := render(t, publicScan())
	if !strings.Contains(b.Text, "+69 lower") {
		t.Errorf("lower severities were not summarised:\n%s", b.Text)
	}
	if strings.Contains(b.Text, "67 Minimal") {
		t.Errorf("a Minimal count still leads a line:\n%s", b.Text)
	}
}

func TestAnApplicationWithNothingOpenSaysSo(t *testing.T) {
	s := deepScan()
	s.AppState.Active = Counts{}
	s.AppState.New = Counts{}
	s.AppState.Reopened = Counts{}
	if b := render(t, s); !strings.Contains(b.Text, "nothing open") {
		t.Errorf("an application with no open findings was rendered blank:\n%s", b.Text)
	}
}

func TestTheTilesCountOnlyScansThatFinished(t *testing.T) {
	s := deepScan()
	s.Complete = false
	s.Status = "Canceled"
	b := render(t, s, publicScan())
	// publicScan has one Serious active; deepScan's 23 Urgent came from a
	// crawl that stopped partway and must not be totalled.
	if strings.Contains(b.HTML, ">23<") {
		t.Errorf("a partial crawl's counts reached the severity tiles:\n%s", b.HTML)
	}
}

// ─── what changed ───────────────────────────────────────────────────────────

func TestChangedUsesTheSameFloorAsAttention(t *testing.T) {
	// The two disagreeing is how an unauthenticated scan's five reopened
	// Minimal findings became the lead item in the section meant to carry
	// the week's actionable news.
	b := render(t, deepScan(), publicScan())

	changed := b.Text[strings.Index(b.Text, "CHANGED THIS WEEK"):]
	if strings.Contains(changed, "Example Site  ") {
		t.Errorf("Minimal-only churn was listed as a change:\n%s", changed)
	}
	if !strings.Contains(changed, "Example Portal") {
		t.Error("the application with 2 new Critical was not listed")
	}
}

func TestLowerSeverityChurnIsCountedRatherThanDropped(t *testing.T) {
	// Quiet is not the same as absent.
	b := render(t, deepScan(), publicScan())
	if !strings.Contains(b.Text, "1 other application(s) had Medium or Minimal") {
		t.Errorf("churn below the floor vanished entirely:\n%s", b.Text)
	}
}

func TestOnlyNewAndReopenedFindingsGetDetail(t *testing.T) {
	// The backlog is a remediation programme; what appeared since the last
	// scan is what a weekly report exists to surface.
	b := render(t, deepScan())
	if !strings.Contains(b.Text, "150084") || !strings.Contains(b.Text, "150124") {
		t.Error("a NEW or REOPENED finding is missing from the detail")
	}
	if strings.Contains(b.Text, "150999") {
		t.Errorf("an ACTIVE backlog finding was listed as a change:\n%s", b.Text)
	}
}

func TestFindingDetailCarriesTheUrlAndParameter(t *testing.T) {
	// Without these the reader has to open Qualys to know where to look,
	// which is the "go look in the portal" outcome this lane exists to avoid.
	b := render(t, deepScan())
	if !strings.Contains(b.Text, "https://portal.example/search") {
		t.Error("the vulnerable URL is missing")
	}
	if !strings.Contains(b.Text, "parameter: q") {
		t.Error("the vulnerable parameter is missing")
	}
}

func TestDetailIsCappedButTheCountIsNot(t *testing.T) {
	s := deepScan()
	s.Findings = nil
	for i := 0; i < 30; i++ {
		s.Findings = append(s.Findings, Finding{
			ID: "1", Title: "x", Severity: 3, Status: "NEW", URL: "https://x.example/"})
	}
	b := render(t, s)
	if !strings.Contains(b.Text, "and 18 more") {
		t.Errorf("the cap did not state the true remainder:\n%s", b.Text)
	}
}

func TestWithoutApiDetailTheReportSaysSo(t *testing.T) {
	// A missing detail section must not read as "no findings". The counts
	// come from the email and are still true.
	s := deepScan()
	s.Findings = nil
	b := render(t, s)
	if !strings.Contains(b.Text, "detail not available") {
		t.Errorf("absent detail was indistinguishable from none found:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "2 Critical") {
		t.Error("the counts from the notification were lost with the detail")
	}
}

// ─── the rest ───────────────────────────────────────────────────────────────

func TestAnIncompleteScanReportsNoCounts(t *testing.T) {
	s := deepScan()
	s.Complete = false
	s.Status = "Canceled"
	b := render(t, s)

	if !strings.Contains(b.Text, "did not complete") {
		t.Errorf("an incomplete scan was not flagged:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "never finished") {
		t.Error("the report does not explain why its counts are withheld")
	}
	if strings.Contains(b.Text, "23 Urgent") {
		t.Errorf("a partial crawl's counts were printed as a result:\n%s", b.Text)
	}
	if !strings.Contains(b.Subject, "INCOMPLETE") {
		t.Errorf("Subject = %q", b.Subject)
	}
}

func TestNoScansIsNotRenderedAsAQuietWeek(t *testing.T) {
	// Zero scans may mean a scheduling problem. "Nothing to report" would be
	// the same text a genuinely clean week produces.
	b := Render(nil, weekEnding())
	if !strings.Contains(b.Text, "scheduling problem") {
		t.Errorf("an empty week did not raise the possibility:\n%s", b.Text)
	}
	// Still a whole document - an unbalanced one renders as a blank mail.
	if !strings.HasSuffix(strings.TrimSpace(b.HTML), "</html>") {
		t.Error("the empty-week HTML is not a closed document")
	}
}

func TestNothingFromAScanBecomesAClickableLink(t *testing.T) {
	s := deepScan()
	s.App = `Evil</p><script>alert(1)</script>`
	s.Findings[0].URL = "https://evil.example/pwn"
	b := render(t, s)

	if strings.Contains(b.HTML, "<a href") {
		t.Errorf("an anchor reached the HTML:\n%s", b.HTML)
	}
	for _, bad := range []string{"<script>", "</script>"} {
		if strings.Contains(b.HTML, bad) {
			t.Errorf("unescaped %q reached the HTML", bad)
		}
	}
}

func TestTheSeparatorInAChangeLineIsNotEscapedIntoView(t *testing.T) {
	// The HTML path joins "new: ..." and "reopened: ..." with a non-breaking
	// space entity. Escaping the joined string rather than each part put a
	// literal "&nbsp;" in the mail.
	b := render(t, deepScan())
	if strings.Contains(b.HTML, "&amp;nbsp;") {
		t.Error("an HTML entity was escaped into visible text")
	}
}

func TestTheReportIsStableAcrossRuns(t *testing.T) {
	// Two runs over the same week must produce the same document, or a diff
	// between weeks stops meaning anything.
	first := render(t, deepScan(), publicScan()).Text
	for i := 0; i < 20; i++ {
		if got := render(t, publicScan(), deepScan()).Text; got != first {
			t.Fatal("report ordering depends on input order")
		}
	}
}

func TestAnUnusableReportLinkIsStatedNotDropped(t *testing.T) {
	s := deepScan()
	s.ReportURL = ""
	s.LinkProblem = "link does not resolve to an allowed host: evil.example"
	b := render(t, s)
	if !strings.Contains(b.Text, "was not usable") {
		t.Errorf("a rejected link vanished silently:\n%s", b.Text)
	}
}

// ─── the one clickable link ─────────────────────────────────────────────────

const portalLink = "https://qualysguard.qg3.apps.qualys.com/portal-front/was/scan/123"

// allowQualys registers the one portal host these tests trust, and puts the
// registry back afterwards so no test depends on another's leftovers.
func allowQualys(t *testing.T) {
	t.Helper()
	saved := portalHosts
	portalHosts = map[string]map[string]bool{}
	AllowPortalHosts("qualys-was", "qualysguard.qg3.apps.qualys.com")
	t.Cleanup(func() { portalHosts = saved })
}

func TestAPortalLinkWeBuiltIsClickable(t *testing.T) {
	// The operator's call: links this lane builds from the API scan record
	// are clickable; everything that arrived in mail stays plain text.
	allowQualys(t)
	s := deepScan()
	s.PortalURL = portalLink
	b := render(t, s)
	if !strings.Contains(b.HTML, `<a href="`+portalLink+`"`) {
		t.Errorf("a verified portal link did not become an anchor:\n%s", b.HTML)
	}
	if strings.Count(b.HTML, "<a href") != 1 {
		t.Errorf("want exactly one anchor - the portal link - got %d",
			strings.Count(b.HTML, "<a href"))
	}
}

func TestTheEmailLinkStaysPlainTextEvenBesideAPortalLink(t *testing.T) {
	allowQualys(t)
	withPortal := deepScan()
	withPortal.PortalURL = portalLink
	mailOnly := publicScan()
	mailOnly.ReportURL = "https://qualysguard.qg3.apps.qualys.com/was/#/reports/y"
	b := render(t, withPortal, mailOnly)
	if strings.Contains(b.HTML, `href="https://qualysguard.qg3.apps.qualys.com/was/`) {
		t.Error("a link that arrived in mail was made clickable")
	}
	if !strings.Contains(b.HTML, "/was/#/reports/y") {
		t.Error("the email's link was dropped instead of printed as text")
	}
}

func TestAPortalLinkThatFailsTheCheckIsNeverPrinted(t *testing.T) {
	// Not printed even as text. The check exists to keep an unexpected URL out
	// of the mail; printing it unlinked would defeat half of that.
	allowQualys(t)
	for _, bad := range []string{
		"https://evil.example/was/scan/123",
		"http://qualysguard.qg3.apps.qualys.com/plain-http",
		"javascript:alert(1)",
		"https://user:pw@qualysguard.qg3.apps.qualys.com/x",
		"https://qualysguard.qg3.apps.qualys.com.evil.example/x",
	} {
		s := deepScan()
		s.PortalURL = bad
		b := render(t, s)
		if strings.Contains(b.HTML, "<a href") {
			t.Errorf("%q became an anchor", bad)
		}
		if strings.Contains(b.Text, bad) || strings.Contains(b.HTML, e(bad)) {
			t.Errorf("%q was printed after failing the check", bad)
		}
		// It falls back to the email's link, which deepScan carries.
		if !strings.Contains(b.Text, "report: https://qualysguard.qg3.apps.qualys.com/was/") {
			t.Errorf("%q: no fallback to the email link", bad)
		}
	}
}

func TestAPortalHostIsTrustedOnlyForItsOwnProvider(t *testing.T) {
	allowQualys(t)
	s := deepScan()
	s.Provider = "invicti"
	s.PortalURL = portalLink
	if b := render(t, s); strings.Contains(b.HTML, "<a href") {
		t.Error("a Qualys host was accepted as the portal for another scanner")
	}
}

func TestWithNothingRegisteredNoLinkIsClickable(t *testing.T) {
	// The failure mode of forgetting AllowPortalHosts is plain text.
	saved := portalHosts
	portalHosts = map[string]map[string]bool{}
	t.Cleanup(func() { portalHosts = saved })
	s := deepScan()
	s.PortalURL = portalLink
	if b := render(t, s); strings.Contains(b.HTML, "<a href") {
		t.Error("an unregistered host produced an anchor")
	}
}

func TestEveryApplicationShowsItsReportLink(t *testing.T) {
	// The link used to be rendered only under CHANGED THIS WEEK, so a quiet
	// application - which on the first send meant all three public sites -
	// never showed one at all.
	s := publicScan()
	s.ReportURL = "https://qualysguard.qg3.apps.qualys.com/was/#/reports/quiet"
	b := render(t, s)
	open := b.Text[strings.Index(b.Text, "OPEN NOW"):strings.Index(b.Text, "CHANGED THIS WEEK")]
	if !strings.Contains(open, "/reports/quiet") {
		t.Errorf("a quiet application's report link is missing from OPEN NOW:\n%s", open)
	}
}

func TestAnIncompleteScanStillShowsItsLink(t *testing.T) {
	// It never reaches OPEN NOW, so the fault entry is its only chance - and
	// "the scan did not finish" is exactly when somebody wants to open it.
	s := deepScan()
	s.Complete = false
	s.Status = "Canceled"
	b := render(t, s)
	faults := b.Text[strings.Index(b.Text, "SCANNER FAULTS"):strings.Index(b.Text, "OPEN NOW")]
	if !strings.Contains(faults, "report: https://qualysguard") {
		t.Errorf("an incomplete scan's link was lost:\n%s", faults)
	}
}

// ─── scans the scanner ran but the mailbox never heard about ───────────────

func emailless() ScanResult {
	return ScanResult{
		Provider: "qualys-was", App: "Example Store", AppID: "9004",
		Complete: true, NoNotification: true, LinksCrawled: 120,
		Status:  "FINISHED",
		Started: time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC),
		Auth:    Auth{Status: "No Authentication specified"},
	}
}

func TestAScanWithNoNotificationIsListedNotCounted(t *testing.T) {
	// Its counts come from an email that never arrived. They are unknown, and
	// printing "nothing open" for it would be the reassuring zero this report
	// exists not to print.
	b := render(t, deepScan(), emailless())
	if !strings.Contains(b.Text, "SCANNED, NO NOTIFICATION (1)") {
		t.Fatalf("the email-less scan was not listed:\n%s", b.Text)
	}
	open := b.Text[strings.Index(b.Text, "OPEN NOW"):strings.Index(b.Text, "SCANNED, NO NOTIFICATION")]
	if strings.Contains(open, "Example Store") {
		t.Errorf("an application with unknown counts appeared under OPEN NOW:\n%s", open)
	}
	if !strings.Contains(b.Text, "counts unknown") || !strings.Contains(b.Text, "not the same as none") {
		t.Error("the report does not say the counts are unknown rather than zero")
	}
	if !strings.Contains(b.HTML, "SCANNED, NO NOTIFICATION (1)") {
		t.Error("the HTML lacks the section the text has")
	}
}

func TestAnEmaillessAuthFailurePrintsNoInventedCount(t *testing.T) {
	s := emailless()
	s.Auth = Auth{Record: "store auth", Status: "Failed"}
	b := render(t, s)
	faults := b.Text[strings.Index(b.Text, "SCANNER FAULTS"):strings.Index(b.Text, "OPEN NOW")]
	if !strings.Contains(faults, "no counts for it at all") {
		t.Errorf("the fault does not say its counts are missing:\n%s", faults)
	}
	if strings.Contains(faults, "0 Urgent") {
		t.Errorf("a count was invented for a scan with no notification:\n%s", faults)
	}
	if strings.Contains(b.Text, "SCANNED, NO NOTIFICATION") {
		t.Error("a faulted email-less scan was listed twice")
	}
}

func TestAnIgnoredFindingIsNotNewWork(t *testing.T) {
	// Somebody set it aside in the scanner's console. Listing it every week
	// as new re-raises a decision a person already made.
	s := deepScan()
	s.Findings = []Finding{
		{ID: "150084", Title: "Reflected XSS", Severity: 5, Status: "NEW", Ignored: true,
			URL: "https://portal.example/search"},
		{ID: "150003", Title: "SQL Injection", Severity: 4, Status: "NEW",
			URL: "https://portal.example/report"},
	}
	b := render(t, s)
	if strings.Contains(b.Text, "150084") {
		t.Errorf("an ignored finding was listed as new:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "150003") {
		t.Error("the finding beside it was lost")
	}
}

func TestAPotentialFindingSaysSo(t *testing.T) {
	s := deepScan()
	s.Findings = []Finding{{ID: "150520", Title: "Information Disclosure",
		Severity: 2, Status: "NEW", Potential: true, URL: "https://portal.example/"}}
	if b := render(t, s); !strings.Contains(b.Text, "potential - not confirmed") {
		t.Errorf("an unconfirmed finding was listed as confirmed:\n%s", b.Text)
	}
}
