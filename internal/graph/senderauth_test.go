package graph

import "testing"

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
