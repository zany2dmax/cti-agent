package appscan

import (
	"regexp"
	"strings"
)

// GENERIC REDACTION OF HEADERS AND JSON-SHAPED TEXT
//
// The first versions matched fixed lists of names (six headers, a dozen JSON
// keys), and a credential under any other name passed through. These match by
// what the name CONTAINS (see strongParam: token, secret, session, credential,
// auth, api key, csrf, jwt, bearer and so on), and read a value to its real end,
// so a nested object, an array of arrays or an escaped string under a secret
// key is removed whole.

const redactedValue = "[redacted by cti-agent]"

// maxSecretMembers is how many credential-named members one pass will handle.
const maxSecretMembers = 2000

var (
	// "key": and \"key\": (JSON inside a JSON string).
	jsonKeyRE = regexp.MustCompile(`(\\?")([^"\\]{1,64})(\\?")\s*:\s*`)
	// {key: and ,key: - a JavaScript object literal, which has no quotes.
	jsKeyRE = regexp.MustCompile(`([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]{0,63})(\s*:\s*)`)
	// {"name":"Cookie","value":"..."} - the shape of a HAR file or an echoed
	// header list, where the secret's NAME is a value.
	harNameRE = regexp.MustCompile(`"name"\s*:\s*"([^"]{1,64})"\s*,\s*"value"\s*:\s*`)
	// A header at the start of a line, and a "name:" anywhere.
	headerNameRE = regexp.MustCompile(`(?im)^([ \t]*)([A-Za-z][A-Za-z0-9-]{0,63})([ \t]*:)`)
	inlineNameRE = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9-]{0,63})[ \t]*:`)
)

// secretName reports whether a header, JSON key or parameter name carries a
// credential or a session.
func secretName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	return strongParam(n) || n == "signature" || strings.Contains(n, "cookie")
}

// valueEnd returns the index just past the value that starts at i: a quoted
// string (an escaped \"...\" one too), a flat or nested object or array, or a
// scalar. -1 when it cannot be delimited, in which case nothing is changed.
func valueEnd(s string, i int) int {
	const limit = 16 << 10 // a credential's value is short; an unbalanced bracket must not cost a scan to the end
	if i >= len(s) {
		return -1
	}
	max := i + limit
	if max > len(s) {
		max = len(s)
	}
	switch {
	case strings.HasPrefix(s[i:], `\"`):
		if j := strings.Index(s[i+2:max], `\"`); j >= 0 {
			return i + 2 + j + 2
		}
		return -1
	case s[i] == '"' || s[i] == '\'':
		q := s[i]
		for j := i + 1; j < max; j++ {
			switch s[j] {
			case '\\':
				j++
			case q:
				return j + 1
			}
		}
		return -1
	case s[i] == '{' || s[i] == '[':
		depth := 0
		for j := i; j < max; j++ {
			switch s[j] {
			case '"', '\'':
				q := s[j]
				for j++; j < max && s[j] != q; j++ {
					if s[j] == '\\' {
						j++
					}
				}
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return j + 1
				}
			}
		}
		return -1
	}
	j := i
	for j < max && !strings.ContainsRune(",}] \t\r\n", rune(s[j])) {
		j++
	}
	if j == i {
		return -1
	}
	return j
}

// redactValues replaces the value after every match of re whose name group
// passes match, then moves on past it.
func redactValues(s string, re *regexp.Regexp, nameGroup int, match func(string) bool) string {
	var b strings.Builder
	last := 0
	seen := 0
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < last {
			continue
		}
		if !match(s[m[2*nameGroup]:m[2*nameGroup+1]]) {
			continue
		}
		// Bounded work: each secret-named member costs at most one capped scan,
		// and a text with thousands of them (built to make this slow) is cut
		// short, failing closed, not scanned for ever.
		if seen++; seen > maxSecretMembers {
			b.WriteString(s[last:m[0]])
			b.WriteString(`"` + redactedValue + `" [rest of text removed: too many credential fields to check]`)
			return b.String()
		}
		start := m[1]
		end := valueEnd(s, start)
		if end < 0 {
			continue
		}
		repl := `"` + redactedValue + `"`
		if strings.HasPrefix(s[start:], `\"`) {
			repl = `\"` + redactedValue + `\"`
		}
		b.WriteString(s[last:start])
		b.WriteString(repl)
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactJSONSecrets removes the value of every JSON or JavaScript-literal member
// whose key names a credential, and the value of a {"name":..,"value":..} pair
// whose name does.
func redactJSONSecrets(s string) string {
	s = redactValues(s, jsonKeyRE, 2, secretName)
	s = redactValues(s, jsKeyRE, 2, secretName)
	return redactValues(s, harNameRE, 1, secretName)
}

// eol returns the end of the line starting at i, extended over folded
// continuation lines (the next line begins with a space or a tab).
func eol(s string, i int) int {
	for {
		j := i
		for j < len(s) && s[j] != '\n' && s[j] != '\r' {
			j++
		}
		k := j
		if k < len(s) && s[k] == '\r' {
			k++
		}
		if k < len(s) && s[k] == '\n' {
			k++
		}
		if k < len(s) && (s[k] == ' ' || s[k] == '\t') && k > j {
			i = k
			continue
		}
		return j
	}
}

// redactGenericHeaders removes the value of every header line whose name carries
// a credential (X-Access-Token, X-CSRF-Token, X-Amz-Security-Token, Api-Key,
// X-Session-Id, ...), not only the six the fixed list names.
func redactGenericHeaders(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range headerNameRE.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < last || !secretName(s[m[4]:m[5]]) {
			continue
		}
		end := eol(s, m[1])
		b.WriteString(s[last:m[1]])
		b.WriteString(" " + redactedValue)
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactInlineHeaders is redactGenericHeaders for a header that is not at the
// start of a line: a header dump on one line, an echo inside HTML. The value
// runs to the end of the line or the next tag.
func redactInlineHeaders(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range inlineNameRE.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < last || !secretName(s[m[2]:m[3]]) {
			continue
		}
		end := m[1]
		for end < len(s) && s[end] != '\r' && s[end] != '\n' && s[end] != '<' {
			end++
		}
		if strings.TrimSpace(s[m[1]:end]) == redactedValue {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(s[m[2]:m[3]] + ": " + redactedValue)
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}
