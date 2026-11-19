package triage

import (
	"strings"
	"testing"
)

func TestIntelMarkers(t *testing.T) {
	for _, c := range []struct {
		name, body string
		intel      bool
	}{
		{"W9 thread", "Hi, please send the corrected W9 for Francis Marion Tire. Invoice 4471, PO 99812. Thanks!", false},
		{"ACH form", "Attached is our ACH form. Routing 021000021, account ending 4421. Call 555-0100.", false},
		{"link with a token", "Sign here: https://docs.example.com/s/0123456789abcdef0123456789abcdef?x=1", false},
		{"private IP", "The printer is at 10.1.2.3 and 192.168.0.10.", false},
		{"CVE", "Fwd: Microsoft says CVE-2026-1234 is exploited.", true},
		{"technique", "The actor uses T1566.002 spear-phishing links.", true},
		{"defanged domain", "Block evil[.]example and its C2.", true},
		{"defanged link", "Payload at hxxp://bad.example/x.exe", true},
		{"public IP", "C2 at 203.0.113.50 on port 443.", true},
		{"hash", "SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
	} {
		got := IntelMarkers(c.body)
		if (len(got) > 0) != c.intel {
			t.Errorf("%s: markers = %v, want intel=%v", c.name, got, c.intel)
		}
	}
	if got := strings.Join(IntelMarkers("CVE-2026-1234 and evil[.]example"), ", "); !strings.Contains(got, "1 CVE ID(s)") || !strings.Contains(got, "1 defanged indicator(s)") {
		t.Errorf("reasons = %q", got)
	}
}
