package appscan

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// REDACTION OF SCANNER EVIDENCE
//
// A scanner's evidence is the HTTP it sent and received while logged in as
// the scan account: its Cookie, Set-Cookie and Authorization headers are a
// working session. Anything this fleet writes from that evidence - a probe
// dump, ticket text - goes through Redact first. (The scanner's own report,
// attached as-is, is the exception, and the ticket says so.)

var (
	// A secret header and any folded continuation lines after it.
	secretHeaderRE = regexp.MustCompile(
		`(?im)^([ \t]*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token)[ \t]*:)[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*`)
	// Qualys sends request/response headers base64-encoded in verbose output.
	b64BlockRE = regexp.MustCompile(`(?s)<(headers|contents|request|response|body)(\s[^>]*)?>\s*(?:<!\[CDATA\[)?\s*([A-Za-z0-9+/=\r\n]{16,})\s*(?:\]\]>)?\s*</(?:headers|contents|request|response|body)>`)
)

// Redact removes credential-bearing header values from text. Base64 blocks
// inside the scanner's XML that decode to text are decoded first and
// redacted in the clear, marked as decoded - a redaction that only looked at
// the encoded form would pass every cookie through untouched.
func Redact(s string) string {
	s = b64BlockRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := b64BlockRE.FindStringSubmatch(m)
		raw := strings.NewReplacer("\r", "", "\n", "").Replace(sub[3])
		dec, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || !utf8.Valid(dec) || !printable(dec) {
			// Fail closed: what cannot be read cannot be checked for a
			// cookie, so it does not go out.
			return "<" + sub[1] + ">[encoded block removed by cti-agent: not readable text, " +
				"so it could not be checked for credentials]</" + sub[1] + ">"
		}
		return "<" + sub[1] + " decoded=\"cti-appreport\"><![CDATA[" +
			strings.ReplaceAll(redactHeaders(string(dec)), "]]>", "]]&gt;") + "]]></" + sub[1] + ">"
	})
	return redactHeaders(s)
}

func redactHeaders(s string) string {
	s = secretHeaderRE.ReplaceAllString(s, "$1 [redacted by cti-agent]")
	// The same headers mid-line - a header dump on one line, an echo inside
	// HTML - and token-shaped JSON values, which no line anchor catches.
	s = inlineHeaderRE.ReplaceAllString(s, "$1: [redacted by cti-agent]")
	s = jsonSecretRE.ReplaceAllString(s, `$1"[redacted by cti-agent]"`)
	// Since the owner report (November 2026) this evidence leaves the company,
	// to the developers of the application, so three more shapes go:
	//
	//   a cookie set by script, which Qualys prints as "name=value; path=/;
	//   domain=..." with no Set-Cookie header in front - the value goes, the
	//   name and attributes stay so the finding still reads;
	s = cookieLineRE.ReplaceAllString(s, "${1}=[value removed]${2}")
	//   a form field carrying a token (<input name="csrf_token" value="...">);
	s = secretInputRE.ReplaceAllString(s, `${1}[redacted by cti-agent]${3}`)
	s = secretInputRevRE.ReplaceAllString(s, `${1}[redacted by cti-agent]${3}`)
	//   and bearer or JWT tokens anywhere, outside a header.
	s = bearerRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	s = basicRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	//   and the request's own headers as a page prints them back - phpinfo()
	//   rows, $_SERVER / $_COOKIE dumps - which Qualys keeps as the proof of
	//   an information-disclosure finding. PHP_AUTH_PW is the scan account's
	//   password in clear under basic auth.
	s = serverVarRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	//   phpinfo()'s own header table names the header with no colon, in a
	//   cell; Digest credentials are as live as Basic ones; and a cookie dump
	//   ($_COOKIE[...], print_r, a name/value table) shows every cookie by
	//   name, so every $_COOKIE key and every well-known session name goes.
	s = headerCellRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	s = digestRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	s = cookieDumpRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	s = sessionNameRE.ReplaceAllString(s, "${1}[redacted by cti-agent]")
	return jwtRE.ReplaceAllString(s, "[token redacted by cti-agent]")
}

var (
	// name=value followed by a cookie attribute. The value stops at ";",
	// space or a quote, as a cookie value does.
	cookieLineRE = regexp.MustCompile(
		`(?i)\b([A-Za-z0-9_.!#$%&'*+^|~-]{1,128})=[^;\s"'<>]+(;\s*(?:path|domain|expires|max-age|secure|httponly|samesite|partitioned)\b)`)
	// An input whose name says it is a secret: value after name, or before.
	secretInputRE = regexp.MustCompile(
		`(?i)(<input\b[^>]*\bname\s*=\s*["']?[^"'\s>]*(?:csrf|xsrf|token|nonce|session|secret|auth|passw|api_?key)[^"'\s>]*["']?[^>]*\bvalue\s*=\s*["'])([^"']*)(["'])`)
	secretInputRevRE = regexp.MustCompile(
		`(?i)(<input\b[^>]*\bvalue\s*=\s*["'])([^"']*)(["'][^>]*\bname\s*=\s*["']?[^"'\s>]*(?:csrf|xsrf|token|nonce|session|secret|auth|passw|api_?key))`)
	bearerRE = regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
	basicRE  = regexp.MustCompile(`(?i)(\bbasic\s+)[A-Za-z0-9+/=]{8,}`)
	digestRE = regexp.MustCompile(`(?i)(\bdigest\s+)(?:username|realm|nonce|response)\s*=[^<\r\n]*`)
	// cell boundary: </td><td ...> (or th), whitespace allowed.
	headerCellRE = regexp.MustCompile(
		`(?i)(<t[dh][^>]*>\s*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token)\s*</t[dh]>\s*<t[dh][^>]*>)[^<]*`)
	cookieDumpRE = regexp.MustCompile(
		`(?i)(\$_COOKIE\[\s*['"]?[^\]'"<]{1,128}['"]?\s*\]\s*(?:</t[dh]>\s*<t[dh][^>]*>|=>|=)?\s*)[^<\r\n]+`)
	sessionNameRE = regexp.MustCompile(
		`(?i)((?:\[|<t[dh][^>]*>\s*)(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID[A-Z]*|sid|session_?id|laravel_session|ci_session|connect\.sid|wordpress_logged_in_[0-9a-f]*|wordpress_sec_[0-9a-f]*|wp_session[a-z_]*)(?:\]\s*=>|\s*</t[dh]>\s*<t[dh][^>]*>)\s*)[^<\r\n]+`)
	// A server variable carrying the request's credentials, then its value:
	// in a table cell (phpinfo), after "=>" (print_r) or "=" / ":" / space.
	serverVarRE = regexp.MustCompile(
		`(?i)((?:\$_(?:SERVER|COOKIE)\[['"]?)?\b(?:HTTP_COOKIE|HTTP_AUTHORIZATION|REDIRECT_HTTP_AUTHORIZATION|PHP_AUTH_(?:USER|PW|DIGEST)|HTTP_X_[A-Z0-9_]*(?:TOKEN|KEY|AUTH)[A-Z0-9_]*)\b['"]?\]?\s*(?:</t[dh]>\s*<t[dh][^>]*>|=>|[=:])?\s*)[^<\r\n]+`)
	jwtRE = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)

	inlineHeaderRE = regexp.MustCompile(
		`(?i)\b(set-cookie|cookie|authorization|proxy-authorization|x-api-key|x-auth-token)\s*:[^\r\n<"]*`)
	jsonSecretRE = regexp.MustCompile(
		`(?i)("(?:access_token|id_token|refresh_token|password|passwd|secret|client_secret|api_?key|session_?id|csrf_?token|cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|\[[^\]]*\])`)
	// urlSecretRE is a query or matrix (;jsessionid=) parameter whose name
	// says it carries a credential or a session.
	urlSecretRE = regexp.MustCompile(
		`(?i)((?:^|[?&;])(?:pass|pwd|password|passwd|token|access_token|id_token|session|sess|sid|jsessionid|phpsessid|aspsessionid|auth|key|apikey|api_key|secret|code|signature|sig|csrf|csrf_token|nonce)=)[^&#;?\s"'<>]*`)
)

// RedactURL replaces the value of every URL parameter named like a
// credential or session id (token=, sid=, ;jsessionid=, ...). The scan
// account's session in a link is as live as its Cookie header.
func RedactURL(s string) string {
	return urlSecretRE.ReplaceAllString(s, "${1}[redacted]")
}

// sessionParamRE are the parameter names whose value is a session or a
// credential, never a payload - RedactURLKeeping never spares them.
var sessionParamRE = regexp.MustCompile(
	`(?i)^(?:pass|pwd|password|passwd|token|access_token|id_token|session|sess|sid|jsessionid|phpsessid|aspsessionid|auth|apikey|api_key|secret|csrf|csrf_token)$`)

// RedactURLKeeping is RedactURL that leaves one parameter alone: the one a
// finding names, whose value is the payload that proves it (a parameter
// called "key" or "code" is as injectable as any other). Its value is the
// scanner's, not the scan account's.
func RedactURLKeeping(s, param string) string {
	param = strings.TrimSpace(param)
	if param == "" {
		return RedactURL(s)
	}
	return urlSecretRE.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.TrimRight(strings.TrimLeft(m, "?&;"), "=")
		if i := strings.IndexByte(m, '='); i >= 0 {
			name = strings.TrimLeft(m[:i], "?&;")
		}
		// Spared only when the parameter is not itself a session or a
		// credential: Qualys files "session ID in URL" findings with the
		// session parameter as the finding's param, and that value is live.
		if strings.EqualFold(name, param) && !sessionParamRE.MatchString(name) {
			return m
		}
		return urlSecretRE.ReplaceAllString(m, "${1}[redacted]")
	})
}

func printable(b []byte) bool {
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
