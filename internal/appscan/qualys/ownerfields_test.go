package qualys

import (
	"encoding/base64"
	"encoding/xml"
	"github.com/zany2dmax/cti-agent/internal/appscan"
	"strings"
	"testing"
)

// A verbose record as the live probe of 2026-11-10 named its elements,
// values made up.
const verboseRecord = `<Finding><id>9</id><uniqueId>u-1</uniqueId><qid>150123</qid>
<name>Cookie Does Not Contain The "HTTPOnly" Attribute</name><type>VULNERABILITY</type>
<severity>2</severity><url>https://app.example.com/a;jsessionid=LIVE1?sid=LIVE2&amp;q=x</url>
<status>REOPENED</status><param>q</param><potential>false</potential>
<detectionScore>50</detectionScore><timesDetected>4</timesDetected>
<cvssV3><base>4.3</base><temporal>4.1</temporal><attackVector>Network</attackVector></cvssV3>
<cwe><count>1</count><list><long>1004</long></list></cwe>
<owasp><count>1</count><list><OWASP><name>A02:2025 Security Misconfiguration</name><code>2</code><url>https://owasp.example</url></OWASP></list></owasp>
<webApp><id>101</id><name>App</name><url>https://app.example.com?token=LIVE3</url></webApp>
</Finding>`

func TestTheVerboseRecordsClassificationIsRead(t *testing.T) {
	var w wasFinding
	if err := xml.Unmarshal([]byte(verboseRecord), &w); err != nil {
		t.Fatal(err)
	}
	f := w.normalise()
	if f.QDS != 50 || f.Times != 4 || f.CVSS != 4.3 || f.CVSSTemporal != 4.1 || f.AttackVector != "Network" {
		t.Errorf("scores: %+v", f)
	}
	if len(f.CWE) != 1 || f.CWE[0] != 1004 || len(f.OWASP) != 1 || f.OWASP[0].Code != "A02" {
		t.Errorf("CWE %v OWASP %+v", f.CWE, f.OWASP)
	}
	if f.Kind != "VULNERABILITY" || f.UniqueID != "u-1" {
		t.Errorf("kind %q id %q", f.Kind, f.UniqueID)
	}
	// A session in the finding's URL or the app's URL never reaches a report.
	for _, s := range []string{f.URL, f.AppURL} {
		if strings.Contains(s, "LIVE") {
			t.Errorf("a session survived in %q", s)
		}
	}
	if !strings.Contains(f.URL, "q=x") {
		t.Errorf("the finding's own parameter was removed: %q", f.URL)
	}
}

func TestAnEncodedProofThatCannotBeCheckedIsRemoved(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: s=LIVE; Path=/\r\n" + strings.Repeat("x", 300)))
	// Cut short, as a truncated response would be: no longer a multiple of 4.
	// Unpadded base64 decodes as it is, so it is checked like any other block:
	// the cookie in it is redacted, and it is no longer passed through encoded.
	if got := maybeBase64(enc[:len(enc)-1]); got == unreadable || strings.Contains(got, enc[:40]) ||
		strings.Contains(appscan.Redact(got), "LIVE") {
		t.Errorf("truncated base64 was passed through or its cookie survived: %.60q", got)
	}
	// Cut so that it cannot be decoded at all (one stray character): removed.
	if got := maybeBase64(enc[:len(enc)-3]); got != unreadable {
		t.Errorf("undecodable base64 was passed through: %.60q", got)
	}
	// Unpadded and short: a cookie in it used to pass straight through.
	unpadded := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte("Cookie: s=LIVE")), "=")
	if got := maybeBase64(unpadded); strings.Contains(appscan.Redact(got), "LIVE") || got == unpadded {
		t.Errorf("an unpadded encoded cookie was not decoded and redacted: %q", got)
	}
	// Text with an encoded block after it: the block is decoded so the
	// header redaction sees it, never left encoded.
	got := maybeBase64("[truncated] " + enc)
	if strings.Contains(got, enc[:40]) {
		t.Error("an encoded run inside text was left encoded")
	}
	if !strings.Contains(got, "Set-Cookie") {
		t.Errorf("a readable encoded run was not decoded for redaction: %.80q", got)
	}
	// Short base64-looking text is text.
	if got := maybeBase64("deadbeefcafe1"); got != "deadbeefcafe1" {
		t.Errorf("short text changed: %q", got)
	}
}

// A short plain-text proof is text, not an encoded blob: it has spaces, and
// base64 does not. (The unpadded-base64 decode must not rewrite it into garbage.)
func TestShortPlainTextProofsAreNotTakenForBase64(t *testing.T) {
	for _, in := range []string{
		"Internal Server Error", "Directory listing enabled", "Access denied for user", "Forbidden You dont have permission",
	} {
		if got := maybeBase64(in); got != in {
			t.Errorf("plain text was changed: %q -> %q", in, got)
		}
	}
}
