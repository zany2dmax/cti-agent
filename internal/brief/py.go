package brief

// The digest is rendered from decoded JSON (the enriched file, or fleet-db's
// rollup), and the Python renderer it replaced read that JSON loosely: a key
// may be missing or null, a count may be an int or a float, and a value is
// printed with str(). These helpers keep those rules, so the email reads the
// same as it did.

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/pyfmt"
)

type obj = map[string]any

// get is m.get(k): nil when m is not an object or has no k.
func get(m any, k string) any {
	if o, ok := m.(obj); ok {
		return o[k]
	}
	return nil
}

// getOr is m.get(k, def): def only when the key is absent, not when null.
func getOr(m any, k string, def any) any {
	if o, ok := m.(obj); ok {
		if v, ok := o[k]; ok {
			return v
		}
	}
	return def
}

func has(m any, k string) bool {
	o, ok := m.(obj)
	if !ok {
		return false
	}
	_, ok = o[k]
	return ok
}

func asObj(v any) obj {
	o, _ := v.(obj)
	return o
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// truthy is Python truth: None, False, 0, "" and empty containers are false.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return err != nil || f != 0
	case []any:
		return len(x) > 0
	case obj:
		return len(x) > 0
	}
	return true
}

// or is `a or b`.
func or(a, b any) any {
	if truthy(a) {
		return a
	}
	return b
}

// num is a value as a number for comparing (0 when it is not one).
func num(v any) float64 {
	switch x := v.(type) {
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64)
		return f
	case bool:
		if x {
			return 1
		}
	case int:
		return float64(x)
	case float64:
		return x
	}
	return 0
}

// isOne is `v == 1`: a number equal to one (True counts, as in Python).
func isOne(v any) bool {
	switch v.(type) {
	case json.Number, bool, int, float64:
		return num(v) == 1
	}
	return false
}

// str is Python's str().
func str(v any) string { return pyfmt.Value(v) }

// sget is str(m.get(k) or "") - the common "text or nothing" read.
func sget(m any, k string) string { return str(or(get(m, k), "")) }

// esc is the renderer's esc(): None is "", anything else str() and then
// html.escape with quotes.
func esc(v any) string {
	if v == nil {
		return ""
	}
	return htmlEscape(str(v))
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")

func htmlEscape(s string) string { return htmlEscaper.Replace(s) }

// cut is s[:n] by character.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// padRight is format(s, "<n").
func padRight(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s
}

// plural is "s" unless v == 1.
func plural(v any) string {
	if isOne(v) {
		return ""
	}
	return "s"
}

// pyInt is int(v) for a count read from JSON: a float is truncated, a
// numeric string parsed, anything else 0.
func pyInt(v any) int {
	switch x := v.(type) {
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return int(i)
		}
		f, _ := strconv.ParseFloat(string(x), 64)
		return int(f)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(x))
		return i
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

// pyFloat is float(v): a number, or a numeric string.
func pyFloat(v any) float64 {
	if s, ok := v.(string); ok {
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f
	}
	return num(v)
}

// digitsKey orders the number part of a ticket key as an integer of any
// size, as Python's int() would.
func digitsKey(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return new(big.Int)
	}
	return n
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// join is sep.join(str(x) for x in list).
func join(list []any, sep string) string {
	parts := make([]string, len(list))
	for i, v := range list {
		parts[i] = str(v)
	}
	return strings.Join(parts, sep)
}

func firstN(l []any, n int) []any {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// Str is Python's str() of a decoded JSON value, for the command's log line.
func Str(v any) string { return str(v) }
