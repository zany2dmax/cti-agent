package appscan

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRedactPlainHeaders(t *testing.T) {
	in := "GET / HTTP/1.1\nHost: app.example.com\nCookie: SESSION=abc123\nAuthorization: Basic dXNlcjpwYXNz\n" +
		"  set-cookie : JSESSIONID=zzz; HttpOnly\nAccept: */*\n"
	out := Redact(in)
	for _, leak := range []string{"abc123", "dXNlcjpwYXNz", "zzz"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q survived:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"Host: app.example.com", "Accept: */*", "Cookie: [redacted by cti-agent]"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q:\n%s", keep, out)
		}
	}
}

func TestRedactBase64Headers(t *testing.T) {
	hdr := base64.StdEncoding.EncodeToString([]byte("Host: app.example.com\r\nCookie: SESSION=secret-session\r\n"))
	in := "<PayloadInstance><request><headers><![CDATA[" + hdr + "]]></headers></request></PayloadInstance>"
	out := Redact(in)
	if strings.Contains(out, "secret-session") || strings.Contains(out, hdr) {
		t.Fatalf("encoded cookie survived:\n%s", out)
	}
	if !strings.Contains(out, `decoded="cti-appreport"`) || !strings.Contains(out, "Host: app.example.com") {
		t.Fatalf("not decoded:\n%s", out)
	}
}

// Fail closed: a block that cannot be decoded to text is removed, not passed.
func TestRedactRemovesUnreadableBase64(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	out := Redact("<contents>" + blob + "</contents>")
	if strings.Contains(out, blob) || !strings.Contains(out, "removed by cti-agent") {
		t.Fatalf("binary blob passed: %s", out)
	}
}

func TestRedactTagWithAttributes(t *testing.T) {
	hdr := base64.StdEncoding.EncodeToString([]byte("Set-Cookie: S=leaky-value\r\n"))
	out := Redact(`<headers base64="true">` + hdr + `</headers>`)
	if strings.Contains(out, "leaky-value") || strings.Contains(out, hdr) {
		t.Fatalf("attributed tag passed: %s", out)
	}
}

// Credentials mid-line and in JSON are caught, not only header lines.
func TestRedactCatchesInlineHeadersAndJSONSecrets(t *testing.T) {
	in := `<pre>HTTP/1.1 200 OK Set-Cookie: sid=abc123; Path=/</pre> {"access_token":"tok-xyz","user":"a"}`
	out := Redact(in)
	for _, leak := range []string{"abc123", "tok-xyz"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q survived: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"user":"a"`) {
		t.Errorf("ordinary JSON was removed: %s", out)
	}
}

func TestRedactURLScrubsSessionAndTokenParameters(t *testing.T) {
	in := "https://app.example.com/a;jsessionid=S1?q=shoes&token=T2&sid=S3#x"
	out := RedactURL(in)
	for _, leak := range []string{"S1", "T2", "S3"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q survived: %s", leak, out)
		}
	}
	if !strings.Contains(out, "q=shoes") {
		t.Errorf("an ordinary parameter was removed: %s", out)
	}
}
