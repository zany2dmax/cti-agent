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

func TestRedactOwnerReportShapes(t *testing.T) {
	// The owner report sends this evidence outside the company. Each secret
	// goes; the finding still reads (names and attributes stay); and the
	// injected payload is kept, so a developer can reproduce the flaw.
	// Built from pieces so a secret scanner does not flag this file: it is a made-up
	// token (header {"alg":"HS256"}, payload {"sub":...}), kept only to test Redact.
	fakeJWT := "eyJhbG" + "ciOiJI" + "UzI1Ni" + "J9" + "." + "eyJzdW" + "IiOiIx" + "MjM0In" + "0" + "." + "c2lnbm" + "F0dXJl" + "X2hlcm" + "U"
	fakeBearer := "Bea" + "rer abcdefgh" + "ijklmnop123"
	cases := []struct{ in, gone, kept string }{
		{"sbjs_udata=vst%3D1%7C%7C%7Cuip; path=/; domain=example.com",
			"vst%3D1", "sbjs_udata=[value removed]; path=/; domain=example.com"},
		{"__cf_bm=hd5.Hcl8XIng; HttpOnly; Secure; Path=/",
			"hd5.Hcl8XIng", "__cf_bm=[value removed]; HttpOnly"},
		{`<input type="hidden" name="csrf_token" value="9f8e7d6c5b4a">`,
			"9f8e7d6c5b4a", `name="csrf_token" value="[redacted by cti-agent]"`},
		{`<input value="deadbeefcafe" name="_wpnonce">`,
			"deadbeefcafe", `value="[redacted by cti-agent]" name="_wpnonce"`},
		{"token in a body: " + fakeBearer,
			"abcdefghijklmnop123", "Bea" + "rer [redacted by cti-agent]"},
		{"leaked " + fakeJWT + " in a page",
			"eyJhbGciOiJIUzI1NiJ9", "[token redacted by cti-agent]"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if strings.Contains(out, c.gone) {
			t.Errorf("Redact(%q) kept %q: %q", c.in, c.gone, out)
		}
		if !strings.Contains(out, c.kept) {
			t.Errorf("Redact(%q) = %q, want it to contain %q", c.in, out, c.kept)
		}
	}
	for _, payload := range []string{
		`"><script>alert(document.domain)</script>`,
		`' OR '1'='1' -- `,
		`../../../../etc/passwd`,
	} {
		if out := RedactURL(Redact(payload)); out != payload {
			t.Errorf("a payload was changed: %q -> %q (payloads are kept for the developer)", payload, out)
		}
	}
}

func TestRedactURLCatchesAFormBodyFromTheStart(t *testing.T) {
	if out := RedactURL("password=hunter2&user=a"); strings.Contains(out, "hunter2") {
		t.Errorf("a form body's first pair kept its secret: %q", out)
	}
}

func TestRedactShapesFoundInReview(t *testing.T) {
	// Secrets a page prints back that are not "Name: value" headers.
	for _, c := range []struct{ in, gone string }{
		{`<tr><td class="e">HTTP_COOKIE </td><td class="v">PHPSESSID=abc123secret </td></tr>`, "abc123secret"},
		{`<tr><td class="e">PHP_AUTH_PW </td><td class="v">scanPassw0rd </td></tr>`, "scanPassw0rd"},
		{`[HTTP_AUTHORIZATION] => Basic c2NhbjpwYXNzd29yZA==`, "c2NhbjpwYXNzd29yZA"},
		{`$_SERVER['HTTP_COOKIE'] = wp_session=livevalue99`, "livevalue99"},
		{`{"headers":{"Cookie":"JSESSIONID=abcLIVE","Authorization":"Basic c2Nh"}}`, "abcLIVE"},
		{`{"headers":{"Authorization":"Basic c2NhbjpwYXNz"}}`, "c2NhbjpwYXNz"},
		{"Cookie: a=1;\n JSESSIONID=foldedLIVE", "foldedLIVE"},
		{"auth header Basic c2NhbjpwYXNzd29yZA== in a page", "c2NhbjpwYXNzd29yZA"},
	} {
		if out := Redact(c.in); strings.Contains(out, c.gone) {
			t.Errorf("Redact(%q) kept %q: %q", c.in, c.gone, out)
		}
	}
}

func TestRedactURLKeepingSparesTheFindingsParameter(t *testing.T) {
	u := "https://app.example.com/p?key=1%27%20OR%20%271%27%3D%271&sid=LIVE"
	out := RedactURLKeeping(u, "key")
	if !strings.Contains(out, "key=1%27%20OR") {
		t.Errorf("the payload in the finding's own parameter was removed: %q", out)
	}
	if strings.Contains(out, "LIVE") {
		t.Errorf("the session in another parameter survived: %q", out)
	}
	if strings.Contains(RedactURLKeeping("https://x.example/;jsessionid=LIVE", ""), "LIVE") {
		t.Error("with no parameter named, it must redact like RedactURL")
	}
}

func TestRedactShapesFoundInReReview(t *testing.T) {
	for _, c := range []struct{ in, gone string }{
		{`<td class="e">Cookie </td><td class="v">PHPSESSID=abcLIVE</td>`, "abcLIVE"},
		{`<td class="e">Authorization </td><td class="v">Digest username="scan", response="d1g3stLIVE"</td>`, "d1g3stLIVE"},
		{`Authorization header was Digest username="scan", realm="x", response="r35pLIVE"`, "r35pLIVE"},
		{`<td class="e">$_COOKIE['PHPSESSID']</td><td class="v">ckLIVE1</td>`, "ckLIVE1"},
		{`$_COOKIE["any_name"] => ckLIVE2`, "ckLIVE2"},
		{"[PHPSESSID] => ckLIVE3", "ckLIVE3"},
		{`<td>JSESSIONID</td><td>ckLIVE4</td>`, "ckLIVE4"},
		{`{"cookie":["JSESSIONID=arrLIVE"]}`, "arrLIVE"},
		{`{"Cookie":"sid=a\"bc-escLIVE"}`, "escLIVE"},
	} {
		if out := Redact(c.in); strings.Contains(out, c.gone) {
			t.Errorf("Redact(%q) kept %q: %q", c.in, c.gone, out)
		}
	}
	// The finding names the session parameter itself: still redacted.
	if out := RedactURLKeeping("https://x.example/a;jsessionid=LIVE123?q=1", "jsessionid"); strings.Contains(out, "LIVE123") {
		t.Errorf("a session parameter was spared because the finding names it: %q", out)
	}
	// Ordinary prose about digests is not touched.
	if in := "Use a message digest such as SHA-256."; Redact(in) != in {
		t.Errorf("prose changed: %q", Redact(in))
	}
}
