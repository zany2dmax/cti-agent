package main

// Python's rules for reading loosely typed events: .get, truthiness, str(),
// len(), and the exceptions a malformed event raised. The Python tool read
// events this way, and its output (and where it stopped) is what the Go
// port must reproduce.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/pyfmt"
	"github.com/zany2dmax/cti-agent/internal/pyjson"
)

type obj = *pyjson.Object

type jsonNumber = json.Number

// pyExc is a Python exception a malformed event raised, carried as a panic
// and recovered where the Python caught it.
type pyExc string

func raise(name string) { panic(pyExc(name)) }

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
		return x.Len() > 0
	}
	return true
}

func or(a, b any) any {
	if truthy(a) {
		return a
	}
	return b
}

// dictOr is `v or {}` about to have .get called on it: a truthy value that
// is not an object raises AttributeError, as it did.
func dictOr(v any) obj {
	if !truthy(v) {
		return pyjson.NewObject()
	}
	o, ok := v.(obj)
	if !ok {
		raise("AttributeError")
	}
	return o
}

func isInt(v any) bool {
	n, ok := v.(json.Number)
	return ok && !strings.ContainsAny(string(n), ".eE")
}

func isNumber(v any) bool { _, ok := v.(json.Number); return ok }

// num is a number's value; True is 1, as Python's arithmetic has it.
func num(v any) float64 {
	switch x := v.(type) {
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64)
		return f
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

// length is len(v): a list, a string (characters) or an object; anything
// else raises TypeError.
func length(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case string:
		return utf8.RuneCountInString(x)
	case obj:
		return x.Len()
	}
	raise("TypeError")
	return 0
}

// iter is `for x in v`: a list's items, a string's characters, an object's
// keys; anything else raises TypeError.
func iter(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case string:
		out := make([]any, 0, len(x))
		for _, r := range x {
			out = append(out, string(r))
		}
		return out
	case obj:
		out := make([]any, len(x.Keys))
		for i, k := range x.Keys {
			out[i] = k
		}
		return out
	case nil:
		raise("TypeError")
	}
	raise("TypeError")
	return nil
}

// str is Python's str().
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return pyjson.Dumps(x, pyjson.Options{})
	}
	return repr(v)
}

// repr is Python's repr() of a decoded value, objects in their own order.
func repr(v any) string {
	switch x := v.(type) {
	case string:
		return pyfmt.ReprString(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case obj:
		parts := make([]string, len(x.Keys))
		for i, k := range x.Keys {
			parts[i] = pyfmt.ReprString(k) + ": " + repr(x.Vals[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return str(v)
}

// hashKey is v as a dict key: Python treats 1, 1.0 and True as one key, and
// a list or object cannot be one at all (TypeError).
func hashKey(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return "s:" + x
	case bool, json.Number:
		return "n:" + strconv.FormatFloat(num(x), 'g', -1, 64)
	}
	raise("TypeError")
	return ""
}

// pySpace is Python's str.isspace, which split() and strip() use.
func pySpace(r rune) bool {
	switch {
	case r >= 0x1c && r <= 0x1f, r == 0x85, r == 0xa0:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r) || r == 0x2028 || r == 0x2029
}

func pyStrip(s string) string { return strings.TrimFunc(s, pySpace) }

// Untrusted text reaches the operator's terminal through `show`. Anything
// that is not printable - ANSI escapes above all - is replaced, and newlines
// are flattened where one line is expected.
var ctrl = regexp.MustCompile("[\x00-\x08\x0b-\x1f\x7f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")

// clean is the Python's clean(text, limit, oneline). limit < 0 is no limit.
func clean(v any, limit int, oneline bool) string {
	text := ""
	if v != nil {
		text = str(v)
	}
	if oneline {
		text = strings.Join(strings.FieldsFunc(text, pySpace), " ")
	}
	text = ctrl.ReplaceAllString(text, "?")
	if limit >= 0 {
		if n := utf8.RuneCountInString(text); n > limit {
			text = string([]rune(text)[:limit]) + fmt.Sprintf("... [%d more chars]", n-limit)
		}
	}
	return text
}

// splitLines is str.splitlines() for text clean() has been through: only
// \n, U+2028 and U+2029 can still be in it.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == 0x2028 || r == 0x2029 {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// sortedKeys is sorted(d): an object's keys in code-point order.
func sortedKeys(o obj) []string {
	keys := append([]string(nil), o.Keys...)
	sort.Strings(keys)
	return keys
}

func sha16(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}
