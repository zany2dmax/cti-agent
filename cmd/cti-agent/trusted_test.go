package main

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// PrimeSec 10786589: a CVE counts as trusted only when an allowlisted sender
// whom Exchange Online authenticated mentioned it.
func TestATrustedSourceIsAnAuthenticatedFeedSender(t *testing.T) {
	fail := "dmarc=fail action=none header.from=intel.example;compauth=fail reason=000"
	feed := []string{"@intel.example"}
	for _, c := range []struct {
		name, from, ar string
		want           bool
	}{
		{"feed, authenticated", "news@intel.example", "dmarc=pass action=none header.from=intel.example;compauth=pass", true},
		{"feed, spoofed", "news@intel.example", fail, false},
		{"stranger, authenticated", "x@attacker.example", "dmarc=pass header.from=attacker.example;compauth=pass", false},
		{"qualys, authenticated", "noreply@notify.qualys.com", "compauth=pass reason=100", true},
		{"feed, no header", "news@intel.example", "", false},
	} {
		m := graph.Message{From: c.from, AuthenticationResults: c.ar}
		if got := trustedSource(m, feed); got != c.want {
			t.Errorf("%s: trusted = %v, want %v", c.name, got, c.want)
		}
	}
}

// The security team is told it can mail a CVE in to be checked. A colleague
// counts when Exchange took the mail as internal, or authenticated the From
// domain; the From address alone does not, and nobody outside the list does.
func TestATeamSourceIsAnAuthenticatedColleague(t *testing.T) {
	team := []string{"@corp.example"}
	internalNoDMARC := "dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=corp.example;"
	for _, c := range []struct {
		name, from, ar, authAs string
		want                   bool
	}{
		{"colleague, internal", "ana@corp.example", internalNoDMARC, "Internal", true},
		{"colleague, dmarc pass", "ana@corp.example", "dmarc=pass action=none header.from=corp.example;compauth=pass", "", true},
		{"colleague address, not internal, no auth", "ana@corp.example", internalNoDMARC, "", false},
		{"colleague address, anonymous", "ana@corp.example", internalNoDMARC, "Anonymous", false},
		{"stranger, internal header", "x@attacker.example", "", "Internal", false},
		{"stranger, authenticated", "x@attacker.example", "dmarc=pass header.from=attacker.example;compauth=pass", "", false},
	} {
		m := graph.Message{From: c.from, AuthenticationResults: c.ar, AuthAs: c.authAs}
		if got := teamSource(m, team); got != c.want {
			t.Errorf("%s: team = %v, want %v", c.name, got, c.want)
		}
	}
	if teamSource(graph.Message{From: "ana@corp.example", AuthAs: "Internal"}, nil) {
		t.Error("an empty team list matched")
	}
	// The gateway setting lets listed feed and scanner domains through the
	// sender check; it must not let a forged From of the org's own domain ask,
	// even when that domain is listed.
	t.Setenv(graph.UnauthenticatedSendersEnv, "corp.example")
	if teamSource(graph.Message{From: "ana@corp.example"}, team) {
		t.Error("FLEET_UNAUTHENTICATED_SENDERS let an unauthenticated colleague address ask")
	}
}

// Advisory triage reads threat intel only: an authenticated sender on the
// threat-intel list. Supplier requests, colleagues and the scanner are not.
func TestIntelSourceIsAnAuthenticatedThreatIntelSender(t *testing.T) {
	pass := "dmarc=pass action=none header.from=intel.example;compauth=pass"
	list := []string{"@intel.example"}
	for _, c := range []struct {
		name, from, ar string
		want           bool
	}{
		{"feed, authenticated", "news@intel.example", pass, true},
		{"feed, spoofed", "news@intel.example", "dmarc=fail header.from=intel.example;compauth=fail", false},
		{"supplier request", "vendor@supplier.example", "dmarc=pass header.from=supplier.example;compauth=pass", false},
		{"qualys is not intel", "noreply@notify.qualys.com", "compauth=pass reason=100", false},
	} {
		m := graph.Message{From: c.from, AuthenticationResults: c.ar}
		if got := intelSource(m, list); got != c.want {
			t.Errorf("%s: intel = %v, want %v", c.name, got, c.want)
		}
	}
	if intelSource(graph.Message{From: "news@intel.example", AuthenticationResults: pass}, nil) {
		t.Error("an empty list matched")
	}
}

func TestTriageSendersDefaultsToTheFeedList(t *testing.T) {
	t.Setenv("TRIAGE_SENDERS", "")
	if got := triageSenders("@a.example, b@c.example"); len(got) != 2 {
		t.Errorf("default = %v", got)
	}
	t.Setenv("TRIAGE_SENDERS", "@intel.example")
	if got := triageSenders("@a.example"); len(got) != 1 || got[0] != "@intel.example" {
		t.Errorf("override = %v", got)
	}
	t.Setenv("TRIAGE_SENDERS", "none")
	if got := triageSenders("@a.example"); got != nil {
		t.Errorf("none = %v", got)
	}
}

// On a tenant whose gateway hides the sender, every feed email fails the check.
// The digest must say so, once per sender, and name what to set; it used to
// stop trusting its feeds without a word.
func TestAnUnvouchedFeedSenderIsReportedOncePerSender(t *testing.T) {
	var buf strings.Builder
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	unvouchedMu.Lock()
	unvouchedSeen = map[string]bool{}
	unvouchedMu.Unlock()
	t.Setenv(graph.UnauthenticatedSendersEnv, "")
	m := graph.Message{From: "intel@feed.example", AuthenticationResults: "dmarc=fail"}
	for i := 0; i < 3; i++ {
		if trustedSource(m, []string{"@feed.example"}) {
			t.Fatal("an unauthenticated feed sender was trusted")
		}
		if intelSource(m, []string{"@feed.example"}) {
			t.Fatal("an unauthenticated intel sender was read")
		}
	}
	out := buf.String()
	if strings.Count(out, "intel@feed.example is not trusted") != 1 {
		t.Fatalf("want one line for the sender, got:\n%s", out)
	}
	if !strings.Contains(out, graph.UnauthenticatedSendersEnv) {
		t.Errorf("the line should say what to set:\n%s", out)
	}
}

// The scanner's own mail is scan results, not threat intel: a Qualys WAS
// notice is full of host names and IPs, and the reader spent a call on each
// one to find nothing. Only a Qualys address listed on TRIAGE_SENDERS is read.
func TestTriagePickLeavesScannerMailOut(t *testing.T) {
	pass := "dmarc=pass action=none header.from=%s;compauth=pass"
	was := graph.Message{From: "noreply@notify.qualys.com", Subject: "CR Web Application Scan Results: Example (18 Nov 2026)",
		AuthenticationResults: fmt.Sprintf(pass, "notify.qualys.com")}
	body := was.Subject + "\nTarget 203.0.113.50 scanned, 4 vulnerabilities, see CVE-2026-1234."
	if save, _, skip := triagePick(was, body, nil); save || skip != skipScanner {
		t.Fatalf("scan notice: save=%v skip=%q", save, skip)
	}
	if save, listed, _ := triagePick(was, body, []string{"noreply@notify.qualys.com"}); !save || !listed {
		t.Fatal("a Qualys address listed on TRIAGE_SENDERS by name was not read")
	}

	feed := graph.Message{From: "news@intel.example", Subject: "Campaign update", AuthenticationResults: fmt.Sprintf(pass, "intel.example")}
	if save, _, _ := triagePick(feed, "C2 at evil[.]example", nil); !save {
		t.Fatal("authenticated mail with an indicator was not read")
	}
	if save, _, _ := triagePick(feed, "Our webinar is on Tuesday.", nil); save {
		t.Fatal("mail with no markers was read")
	}
	forged := graph.Message{From: "news@intel.example", AuthenticationResults: "dmarc=fail header.from=intel.example;compauth=fail"}
	if save, _, skip := triagePick(forged, "C2 at evil[.]example", nil); save || skip != skipUnverified {
		t.Fatalf("forged sender: save=%v skip=%q", save, skip)
	}
	ooo := feed
	ooo.Subject = "Automatic reply: Campaign update"
	if save, _, _ := triagePick(ooo, "C2 at evil[.]example", nil); save {
		t.Fatal("an auto-reply was read")
	}
}
