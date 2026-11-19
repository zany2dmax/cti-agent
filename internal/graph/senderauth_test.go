package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/audit"
)

// PrimeSec 10786562: a From address alone is the sender's claim. These are
// synthetic Exchange Online Authentication-Results values.
func TestSenderAuthenticationReadsTheReceivingServersVerdict(t *testing.T) {
	const from = "Qualys <noreply@notify.qualys.com>"
	for _, c := range []struct {
		name, from, ar string
		want           bool
	}{
		{"compauth pass", from,
			"spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=notify.qualys.com; dkim=pass " +
				"(signature was verified) header.d=notify.qualys.com;dmarc=pass action=none " +
				"header.from=notify.qualys.com;compauth=pass reason=100", true},
		{"dmarc pass for the From domain", from,
			"dmarc=pass action=none header.from=notify.qualys.com", true},
		{"dmarc pass for another domain", from,
			"dmarc=pass action=none header.from=attacker.example", false},
		{"spoof caught", from,
			"spf=fail (sender IP is 198.51.100.7) smtp.mailfrom=notify.qualys.com; dkim=none " +
				"(message not signed) header.d=none;dmarc=fail action=none " +
				"header.from=notify.qualys.com;compauth=fail reason=000", false},
		{"no verdict", from, "spf=pass smtp.mailfrom=notify.qualys.com", false},
		{"no header", from, "", false},
		{"display name trick", "noreply@qualys.com <x@attacker.example>",
			"dmarc=pass action=none header.from=qualys.com", false},
	} {
		ok, why := Message{From: c.from, AuthenticationResults: c.ar}.SenderAuthenticated()
		if ok != c.want {
			t.Errorf("%s: authenticated = %v (%s), want %v", c.name, ok, why, c.want)
		}
		if !ok && why == "" {
			t.Errorf("%s: refused with no reason", c.name)
		}
	}
}

// Only the first Authentication-Results is kept: Exchange Online prepends its
// own, and a copy further down came with the message.
func TestOnlyTheReceivingServersAuthenticationResultsIsKept(t *testing.T) {
	msgs := fetch(t, `{
		"id":"1", "subject":"Qualys: Web Application Vulnerability Scan Results",
		"receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"noreply@notify.qualys.com"}},
		"body":{"contentType":"HTML","content":"x"},
		"internetMessageHeaders":[
			{"name":"Authentication-Results","value":"dmarc=fail action=none header.from=notify.qualys.com;compauth=fail reason=000"},
			{"name":"authentication-results","value":"dmarc=pass header.from=notify.qualys.com;compauth=pass"}
		]
	}`)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if ok, _ := msgs[0].SenderAuthenticated(); ok {
		t.Errorf("a forged second Authentication-Results was trusted: %q", msgs[0].AuthenticationResults)
	}
}

// One AuthAs header is Exchange's verdict. Two means one came with the
// message, and the order Graph lists them in cannot say which: not internal.
func TestADuplicatedAuthAsIsNotInternal(t *testing.T) {
	msg := func(headers string) string {
		return `{"id":"1","subject":"CVE-2026-0001","receivedDateTime":"2026-11-16T10:00:00Z",
			"from":{"emailAddress":{"address":"ana@corp.example"}},
			"body":{"contentType":"Text","content":"x"},"internetMessageHeaders":[` + headers + `]}`
	}
	one := fetch(t, msg(`{"name":"X-MS-Exchange-Organization-AuthAs","value":"Internal"}`))
	if len(one) != 1 || !one[0].Internal() {
		t.Fatalf("one AuthAs: Internal was not internal: %+v", one)
	}
	two := fetch(t, msg(`{"name":"X-MS-Exchange-Organization-AuthAs","value":"Internal"},
		{"name":"x-ms-exchange-organization-authas","value":"Anonymous"}`))
	if len(two) != 1 || two[0].Internal() {
		t.Errorf("two AuthAs headers counted as internal: %q", two[0].AuthAs)
	}
}

// ---- FLEET_UNAUTHENTICATED_SENDERS: a list, not a switch ----

func clearSenderEnv(t *testing.T) {
	t.Helper()
	t.Setenv(UnauthenticatedSendersEnv, "")
	t.Setenv(legacySenderAuthEnv, "")
}

func TestOnlyListedDomainsSkipTheSenderCheck(t *testing.T) {
	clearSenderEnv(t)
	forged := Message{From: "Scanner <noreply@qualys.net>", AuthenticationResults: "dmarc=fail header.from=qualys.net;compauth=fail"}
	if ok, why := forged.VouchedFor(); ok || why == "" {
		t.Fatalf("an unauthenticated message passed with nothing listed: %v %q", ok, why)
	}
	t.Setenv(UnauthenticatedSendersEnv, "Qualys.NET , other.example")
	if ok, _ := forged.VouchedFor(); !ok {
		t.Error("a listed domain (any case, with spaces) was refused")
	}
	for _, from := range []string{"x@evil.example", "x@sub.qualys.net", "x@qualys.net.evil.example", "x@notqualys.net", "", "not an address"} {
		m := Message{From: from, AuthenticationResults: "dmarc=fail"}
		if ok, _ := m.VouchedFor(); ok {
			t.Errorf("From %q passed on a list that names only qualys.net and other.example", from)
		}
	}
}

func TestAnAuthenticatedMessageStillPassesWhateverIsListed(t *testing.T) {
	clearSenderEnv(t)
	m := Message{From: "x@feed.example", AuthenticationResults: "dmarc=pass header.from=feed.example;compauth=pass"}
	if ok, why := m.VouchedFor(); !ok || why != "" {
		t.Fatalf("%v %q", ok, why)
	}
}

func TestTheListTakesExactDomainsNotWildcardsOrAddresses(t *testing.T) {
	good, bad := ParseUnauthenticatedSenders("qualys.net, *.qualys.net, a@b.example, , localhost, .bad.example, ok.example,-x.example")
	if strings.Join(good, ",") != "qualys.net,ok.example" {
		t.Errorf("good = %v", good)
	}
	if len(bad) != 5 {
		t.Errorf("bad = %v", bad)
	}
	clearSenderEnv(t)
	t.Setenv(UnauthenticatedSendersEnv, "*")
	if ok, _ := (Message{From: "x@anything.example", AuthenticationResults: "dmarc=fail"}).VouchedFor(); ok {
		t.Error("a bare * switched the check off")
	}
}

// The old blanket switch is gone: it does nothing except say what replaced it.
func TestTheOldOffSwitchIsNoLongerHonoured(t *testing.T) {
	clearSenderEnv(t)
	t.Setenv(legacySenderAuthEnv, "off")
	ok, why := (Message{From: "x@any.example", AuthenticationResults: "dmarc=fail"}).VouchedFor()
	if ok {
		t.Fatal("FLEET_SENDER_AUTH=off still skips the check")
	}
	if !strings.Contains(why, UnauthenticatedSendersEnv) || !strings.Contains(why, "no longer honoured") {
		t.Errorf("the refusal should name the replacement: %q", why)
	}
}

func TestAcceptingAListedDomainLeavesAnAuditEventOncePerDomain(t *testing.T) {
	clearSenderEnv(t)
	dir := t.TempDir()
	restore := audit.SetDefault(&audit.Logger{Dir: dir, Lane: "cti-vmscan", Actor: "tester", Run: "r", Host: "h", Pid: 1})
	t.Cleanup(restore)
	acceptedM.Lock()
	accepted = map[string]bool{}
	acceptedM.Unlock()
	t.Setenv(UnauthenticatedSendersEnv, "qualys.net")
	m := Message{From: "x@qualys.net", AuthenticationResults: "dmarc=fail"}
	for i := 0; i < 3; i++ {
		if ok, _ := m.VouchedFor(); !ok {
			t.Fatal("listed domain refused")
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	var got strings.Builder
	for _, f := range files {
		b, _ := os.ReadFile(f)
		got.Write(b)
	}
	if n := strings.Count(got.String(), "sender.unauthenticated.accepted"); n != 1 {
		t.Fatalf("want one audit event for three messages from one domain, got %d:\n%s", n, got.String())
	}
	if !strings.Contains(got.String(), `target="qualys.net"`) {
		t.Errorf("event should name the domain:\n%s", got.String())
	}
}
