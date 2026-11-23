// Package pyjson decodes JSON keeping the order of object keys, and writes
// it back exactly as Python's json.dumps does, so a Go port of a Python
// tool (fleet-trace) writes byte-identical files: the same lines, the same
// sizes, and the same hashes of what it does not keep.
//
// Values are nil, bool, json.Number, string, []any and *Object.
package pyjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/pyfmt"
)

// Object is a JSON object with its keys in the order they first appeared.
// A repeated key keeps its first place and its last value, as Python does.
type Object struct {
	Keys []string
	Vals map[string]any
}

// NewObject is an empty object.
func NewObject() *Object { return &Object{Vals: map[string]any{}} }

// Get is o.get(k): nil when absent.
func (o *Object) Get(k string) any {
	if o == nil {
		return nil
	}
	return o.Vals[k]
}

// Has reports whether k is a key.
func (o *Object) Has(k string) bool {
	if o == nil {
		return false
	}
	_, ok := o.Vals[k]
	return ok
}

// Set adds or replaces k, keeping its place.
func (o *Object) Set(k string, v any) {
	if _, ok := o.Vals[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Vals[k] = v
}

// Len is the number of keys.
func (o *Object) Len() int {
	if o == nil {
		return 0
	}
	return len(o.Keys)
}

// Decode parses one JSON value; anything after it but whitespace is an
// error, as in json.loads.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("extra data")
	}
	if rest := bytes.TrimSpace(data[dec.InputOffset():]); len(rest) > 0 {
		return nil, fmt.Errorf("extra data")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			o := NewObject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				o.Set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			l := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return l, nil
		}
		return nil, fmt.Errorf("unexpected %v", x)
	}
	return t, nil
}

// Options are json.dumps's: sort_keys and ensure_ascii.
type Options struct {
	SortKeys    bool
	EnsureASCII bool
}

// Dumps is json.dumps(v) with Python's separators (", " and ": ").
func Dumps(v any, o Options) string {
	var b strings.Builder
	dump(&b, v, o)
	return b.String()
}

func dump(b *strings.Builder, v any, o Options) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(number(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case float64:
		b.WriteString(float(x))
	case string:
		quote(b, x, o.EnsureASCII)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			dump(b, e, o)
		}
		b.WriteByte(']')
	case []string:
		l := make([]any, len(x))
		for i, s := range x {
			l[i] = s
		}
		dump(b, l, o)
	case *Object:
		keys := append([]string(nil), x.Keys...)
		if o.SortKeys {
			sort.Strings(keys)
		}
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			quote(b, k, o.EnsureASCII)
			b.WriteString(": ")
			dump(b, x.Vals[k], o)
		}
		b.WriteByte('}')
	default:
		quote(b, fmt.Sprint(x), o.EnsureASCII)
	}
}

// number writes a JSON number as Python re-serializes what json.loads gave:
// an integer exactly (of any size), anything with a point or an exponent as
// a float's repr.
func number(n json.Number) string {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		if i, ok := new(big.Int).SetString(s, 10); ok {
			return i.String()
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(f, 0) {
		return s
	}
	return float(f)
}

func float(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return pyfmt.Float(f)
}

func quote(b *strings.Builder, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case ascii && r > 0x7f:
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// DecodeBytes is bytes.decode("utf-8", "replace"): each byte that is not
// part of a valid sequence becomes U+FFFD.
func DecodeBytes(p []byte) string {
	if utf8.Valid(p) {
		return string(p)
	}
	var b strings.Builder
	for len(p) > 0 {
		r, n := utf8.DecodeRune(p)
		if r == utf8.RuneError && n == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteRune(r)
		}
		p = p[n:]
	}
	return b.String()
}
