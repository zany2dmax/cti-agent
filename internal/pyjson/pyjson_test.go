package pyjson

import (
	"encoding/json"
	"testing"
)

// The want strings are what Python's json.dumps printed for the same value.
func TestDumpsIndentMatchesPython(t *testing.T) {
	inner := NewObject()
	inner.Set("e", nil)
	inner.Set("f", []any{json.Number("1.5"), true})
	o := NewObject()
	o.Set("a", 1)
	o.Set("b", []any{})
	o.Set("c", NewObject())
	o.Set("d", []any{"x", inner})
	o.Set("g", "café \U0001f600")
	want := `{
  "a": 1,
  "b": [],
  "c": {},
  "d": [
    "x",
    {
      "e": null,
      "f": [
        1.5,
        true
      ]
    }
  ],
  "g": "caf\u00e9 \ud83d\ude00"
}`
	if got := Dumps(o, Options{EnsureASCII: true, Indent: 2}); got != want {
		t.Errorf("indent=2:\n%s\nPython:\n%s", got, want)
	}
	if got, want := Dumps(o, Options{EnsureASCII: true}), `{"a": 1, "b": [], "c": {}, "d": ["x", {"e": null, "f": [1.5, true]}], "g": "caf\u00e9 \ud83d\ude00"}`; got != want {
		t.Errorf("one line:\n%s\nPython:\n%s", got, want)
	}
}
