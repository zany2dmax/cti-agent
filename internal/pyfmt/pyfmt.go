// Package pyfmt writes values the way the fleet's Python lanes wrote them,
// so the Go lanes that replaced them (cti-enrich, cti-brief) produce the same
// text: a CVSS of 10.0 stays "10.0", a missing value is "None" where Python
// printed it, a string's repr is quoted as Python quotes it.
//
// It is for the email and the enriched file, which people and other programs
// already read in that shape. New code with no Python history to match
// should format values the ordinary Go way.
package pyfmt

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Number is a JSON number as Python's str() writes it after json.load: an
// integer as an integer, anything with a point or an exponent as a float.
func Number(n json.Number) string {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return strconv.FormatInt(i, 10)
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	return Float(v)
}

// Float is a float as Python's repr: the shortest text that round-trips,
// ".0" on a whole number, and an exponent only below 1e-4 or from 1e16.
func Float(v float64) string {
	switch {
	case math.IsNaN(v):
		return "nan"
	case math.IsInf(v, 1):
		return "inf"
	case math.IsInf(v, -1):
		return "-inf"
	}
	if v != 0 {
		e := strconv.FormatFloat(v, 'e', -1, 64)
		if exp, err := strconv.Atoi(e[strings.IndexByte(e, 'e')+1:]); err == nil && (exp < -4 || exp >= 16) {
			return e // Go writes 1e-05 and 1e+16 as Python does
		}
	}
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// Value is a decoded JSON value (numbers as json.Number) as Python's str()
// writes it: None, True and False, numbers as Number, lists and objects as
// their repr.
func Value(v any) string {
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
		return Number(x)
	case float64:
		return Float(x)
	case int:
		return strconv.Itoa(x)
	}
	return Repr(v)
}

// Repr is a decoded JSON value as Python's repr().
func Repr(v any) string {
	switch x := v.(type) {
	case string:
		return ReprString(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		// Python keeps insertion order; a decoded map has none, so this is
		// sorted. Only diagnostics print an object.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = ReprString(k) + ": " + Repr(x[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return Value(v)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ReprString is a string as Python's repr(): single quotes unless the string
// holds a single quote and no double quote, with backslash escapes for the
// quote, the backslash and anything unprintable.
func ReprString(s string) string {
	q := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, "\"") {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError:
			b.WriteString(`�`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x` + hex2(int(r)))
		case r < 0x100 && !unicode.IsPrint(r):
			b.WriteString(`\x` + hex2(int(r)))
		case !unicode.IsPrint(r) && r < 0x10000:
			b.WriteString(`\u` + hexN(int(r), 4))
		case !unicode.IsPrint(r):
			b.WriteString(`\U` + hexN(int(r), 8))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

func hex2(n int) string { return hexN(n, 2) }

func hexN(n, width int) string {
	s := strconv.FormatInt(int64(n), 16)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// Percent is a probability as Python's format(p, "."+digits+"%"): times 100,
// rounded half to even on the exact value.
func Percent(p float64, digits int) string {
	return strconv.FormatFloat(p*100, 'f', digits, 64) + "%"
}
