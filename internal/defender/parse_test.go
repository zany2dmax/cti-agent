package defender

import (
	"strings"
	"testing"
	"time"
)

// notification mirrors the structure of a real Defender for Cloud attack-path
// email: the Proofpoint banner, the two hidden preheader divs, the risk banner
// BEFORE the subject heading, the title and description, the detection
// timestamp, the risk/detected-by cards, the four-row details table, the
// call-to-action and the footer with its zero-width spaces.
//
// Every identifier is invented. The production notification names our
// subscription, and this repository is public.
const notification = `
<div id="pfptBanner88f4il9">ZjQcmQRYFpfptBannerStart Caution: this email originated outside the organization. pfptBannerEnd</div>
<div style="display:none;">Read details about the potential attack path in your environment.</div>
<div style="display:none;">Read details about the potential attack path in your environment.</div>
<table class="container section alert"><tr><td>HIGH RISK LEVEL </td></tr></table>
<h1>Microsoft Defender for Cloud found potential attack path in your environment</h1>
<h2 class="margin-bottom-0 no-wrap">Internet exposed Azure VM with high severity vulnerabilities </h2>
<p class="no-wrap">An Azure Virtual Machine is reachable from the internet and has high severity vulnerabilities allows remote code execution. </p>
<p>October 2, 2026 1:38 UTC</p>
<table><tr><td><p>Risk level:</p><h3>High</h3></td><td><p>Detected by</p><h3>Microsoft</h3></td></tr></table>
<h3>Attack path details</h3>
<table class="card-table">
<tr class="border-top"><th class="small-12 large-4">Scope IDs</th><th class="small-12 large-8"><ul class="list-items"><li>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</li></ul></th></tr>
<tr class="border-top"><th class="small-12 large-4">Risk factors</th><th class="small-12 large-8"><ul class="list-items"><li>Internet exposure</li><li>Vulnerabilities</li></ul></th></tr>
<tr class="border-top"><th class="small-12 large-4">Attack story</th><th class="small-12 large-8">1- Attacker can exploit the vulnerabilities via the internet and gain control on the VM<br />2- Attacker can execute code on the Azure VM</th></tr>
<tr class="border-top"><th class="small-12 large-4">Attack path ID</th><th class="small-12 large-8">99999999-dddd-eeee-ffff-222222222222</th></tr>
</table>
<a href="https://urldefense.com/v3/__https://eur.safelink.emails.azure.net/redirect/?destination=https*3A*2F*2Fportal.azure.com*2F*23view*2FMicrosoft_Azure_Security&amp;p=abc__;JSUl!!A!B$">View the attack path &gt;</a>
<div>Microsoft Corporation, One&#8203; Microsoft Way, &#8203;Redmond, WA 98052&#8203;</div>
`

func TestARealShapedNotificationParsesCompletely(t *testing.T) {
	a, problems := Parse(notification)

	if len(problems) != 0 {
		t.Errorf("problems on a well-formed notification: %v", problems)
	}
	if !a.Complete() {
		t.Fatalf("not complete: %+v", a)
	}
	if a.Title != "Internet exposed Azure VM with high severity vulnerabilities" {
		t.Errorf("Title = %q", a.Title)
	}
	if !strings.HasPrefix(a.Description, "An Azure Virtual Machine is reachable") {
		t.Errorf("Description = %q", a.Description)
	}
	if a.RiskLevel != "High" {
		t.Errorf("RiskLevel = %q, want High", a.RiskLevel)
	}
	if a.ID != "99999999-dddd-eeee-ffff-222222222222" {
		t.Errorf("ID = %q", a.ID)
	}
	if len(a.Subscriptions) != 1 || a.Subscriptions[0] != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("Subscriptions = %v", a.Subscriptions)
	}
	if len(a.RiskFactors) != 2 || a.RiskFactors[0] != "Internet exposure" {
		t.Errorf("RiskFactors = %v", a.RiskFactors)
	}
	if len(a.AttackStory) != 2 {
		t.Fatalf("AttackStory = %v", a.AttackStory)
	}
	if strings.HasPrefix(a.AttackStory[0], "1-") {
		t.Errorf("the step number was not stripped: %q", a.AttackStory[0])
	}
	want := time.Date(2026, 10, 2, 1, 38, 0, 0, time.UTC)
	if !a.Detected.Equal(want) {
		t.Errorf("Detected = %v, want %v", a.Detected, want)
	}
	if !strings.HasPrefix(a.PortalURL, "https://portal.azure.com/") {
		t.Errorf("PortalURL = %q (problem: %q)", a.PortalURL, a.LinkProblem)
	}
}

func TestTheBannerDoesNotBecomeTheTitle(t *testing.T) {
	// "HIGH RISK LEVEL" sits between the subject heading and the real title in
	// Microsoft's layout. A naive "first line after the subject" would pick it
	// up, and the digest would report an attack path called HIGH RISK LEVEL.
	a, _ := Parse(notification)
	if strings.Contains(strings.ToUpper(a.Title), "RISK LEVEL") {
		t.Errorf("Title = %q", a.Title)
	}
}

func TestThePreheaderDoesNotBecomeTheTitle(t *testing.T) {
	// Two hidden divs repeat "Read details about the potential attack path in
	// your environment." before anything visible. They contain most of the
	// subject's words, so the match has to be on the distinguishing part.
	a, _ := Parse(notification)
	if strings.HasPrefix(a.Title, "Read details") {
		t.Errorf("a hidden preheader became the title: %q", a.Title)
	}
}

func TestTheProofpointBannerIsNotTreatedAsContent(t *testing.T) {
	a, _ := Parse(notification)
	for _, f := range append([]string{a.Title, a.Description}, a.RiskFactors...) {
		if strings.Contains(strings.ToLower(f), "originated outside") {
			t.Errorf("the Proofpoint banner leaked into %q", f)
		}
	}
}

func TestTheFooterIsNotCollectedAsAFieldValue(t *testing.T) {
	// Without a terminator the LAST label swallows the call to action and the
	// Microsoft postal address. firstGUID happened to still pick the right
	// value, which is the kind of accident that holds until it does not.
	a, _ := Parse(notification)
	for _, s := range a.AttackStory {
		if strings.Contains(s, "Microsoft Corporation") || strings.Contains(s, "View the attack path") {
			t.Errorf("footer text was collected: %q", s)
		}
	}
	if a.ID != "99999999-dddd-eeee-ffff-222222222222" {
		t.Errorf("ID = %q", a.ID)
	}
}

func TestAMissingAttackPathIDIsReportedAsFatalToTheLookup(t *testing.T) {
	// The ID is what the ARM lookup keys on. Without it the notification can
	// never be resolved to a named resource, so it is not a thin finding - it
	// is a broken parse, and must say so.
	body := strings.Replace(notification, "Attack path ID", "Attack path identifier", 1)
	a, problems := Parse(body)

	if a.Complete() {
		t.Error("a notification with no attack path ID was reported complete")
	}
	if !containsSubstr(problems, "cannot be resolved to a resource") {
		t.Errorf("problems do not explain the consequence: %v", problems)
	}
}

func TestATemplateChangeShowsUpAsProblemsNotAsAThinnerEmail(t *testing.T) {
	// Microsoft rewrites this template without notice. The failure that must
	// not happen is a quietly emptier digest section - the whole project's
	// recurring bug. An unrecognised template produces a loud list instead.
	a, problems := Parse(`<html><body><p>Something entirely different</p></body></html>`)

	if a.Complete() {
		t.Error("unrecognised HTML parsed as a complete attack path")
	}
	if len(problems) < 3 {
		t.Errorf("only %d problems reported for an unrecognised template: %v",
			len(problems), problems)
	}
}

func TestALinkThatIsNotThePortalIsAFindingNotSilence(t *testing.T) {
	// A forged Defender notification is cheap and is aimed at the person who
	// reads this digest. Dropping the link quietly would hide the one signal
	// that the mail was not what it claimed.
	body := strings.Replace(notification,
		"https://urldefense.com/v3/__https://eur.safelink.emails.azure.net/redirect/?destination=https*3A*2F*2Fportal.azure.com*2F*23view*2FMicrosoft_Azure_Security&amp;p=abc__;JSUl!!A!B$",
		"https://portal.azure.com.evil.example/#view/x", 1)

	a, problems := Parse(body)

	if a.PortalURL != "" {
		t.Errorf("a lookalike host was accepted: %q", a.PortalURL)
	}
	if a.LinkProblem == "" {
		t.Error("the rejected link left no explanation")
	}
	if !containsSubstr(problems, "did not resolve") {
		t.Errorf("problems do not mention the link: %v", problems)
	}
	// Everything else still parsed, because the finding is still real.
	if !a.Complete() {
		t.Error("a bad link invalidated an otherwise good parse")
	}
}

func TestAnUnreadableTimestampIsLeftZeroRatherThanGuessed(t *testing.T) {
	body := strings.Replace(notification, "October 2, 2026 1:38 UTC", "sometime recently", 1)
	a, _ := Parse(body)
	if !a.Detected.IsZero() {
		t.Errorf("Detected = %v, want the zero time so the caller can fall back", a.Detected)
	}
}

func TestTheBannerIsTheFallbackWhenTheCardIsMissing(t *testing.T) {
	body := strings.Replace(notification, "<p>Risk level:</p><h3>High</h3>", "", 1)
	a, _ := Parse(body)
	if a.RiskLevel != "High" {
		t.Errorf("RiskLevel = %q, want High from the HIGH RISK LEVEL banner", a.RiskLevel)
	}
}

func containsSubstr(ss []string, want string) bool {
	for _, s := range ss {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
