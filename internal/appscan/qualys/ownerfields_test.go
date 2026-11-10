package qualys

import (
	"encoding/base64"
	"encoding/xml"
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
	if got := maybeBase64(enc[:len(enc)-1]); got != unreadable {
		t.Errorf("truncated base64 was passed through: %.60q", got)
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
