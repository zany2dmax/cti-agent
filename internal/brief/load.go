package brief

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// readJSON decodes a file with numbers kept as written. ok is false when it
// is missing or not JSON: every side file is optional.
func readJSON(path string) (any, bool) {
	// #nosec G304 -- a fixed name beside the enriched file the runner named.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func besideEnriched(enriched, suffix string) string {
	return strings.TrimSuffix(enriched, ".json") + suffix
}

// ticketMap is the file cti-jira writes beside the enriched one: the
// cve -> ticket map, the CVEs held for approval, and whether the map was
// listed without re-checking. A file, deliberately: the renderer has no
// Jira credentials and no business having any. Missing is normal.
func ticketMap(enriched string) obj {
	v, _ := readJSON(besideEnriched(enriched, "-tickets.json"))
	o, _ := v.(obj)
	return o
}

// loadProducts is the cve -> product map cti-enrich keeps beside the
// enriched file; only non-empty string names count.
func loadProducts(enriched string) obj {
	abs, err := filepath.Abs(enriched)
	if err != nil {
		abs = enriched
	}
	v, _ := readJSON(filepath.Join(filepath.Dir(abs), "products.json"))
	out := obj{}
	for k, x := range asObj(get(v, "data")) {
		if s, ok := x.(string); ok && s != "" {
			out[k] = s
		}
	}
	return out
}

func loadHeld(m obj) []any {
	var out []any
	for _, h := range asList(m["held"]) {
		if o, ok := h.(obj); ok && truthy(o["cve"]) {
			out = append(out, o)
		}
	}
	if out == nil {
		return []any{}
	}
	return out
}

// loadAdvisories is the cti-advisories/1 report cti-triage wrote beside the
// enriched file, or nil: triage off, nothing to read, failed, or malformed
// (the section then says triage did not report, rather than failing).
func loadAdvisories(enriched string) any {
	v, ok := readJSON(besideEnriched(enriched, "-advisories.json"))
	o, isObj := v.(obj)
	if !ok || !isObj || o["schema"] != "cti-advisories/1" {
		return nil
	}
	if _, ok := o["results"].([]any); !ok {
		return nil
	}
	return o
}

// Prepare fills what the enriched file may lack and adds the renderer's own
// state, all underscore-prefixed: not part of the enriched contract.
func Prepare(data obj, enriched, kind string, triageEnabled bool, now time.Time) {
	if !has(data, "counts") {
		c := obj{}
		for _, p := range SevOrder {
			c[p] = json0
		}
		data["counts"] = c
	}
	if !has(data, "findings") {
		data["findings"] = []any{}
	}
	if !has(data, "total") {
		data["total"] = json.Number(itoa(len(asList(data["findings"]))))
	}
	if !has(data, "generated") {
		data["generated"] = now.UTC().Format("2006-01-02T15:04:05-07:00")
	}
	m := ticketMap(enriched)
	data["_tickets"] = or(m["tickets"], obj{})
	data["_tickets_listed_only"] = truthy(m["listed_only"])
	data["_held"] = loadHeld(m)
	data["_products"] = loadProducts(enriched)
	data["_enriched"] = enriched
	data["_kind"] = kind
	data["_advisories"] = nil
	if kind == "daily" {
		data["_advisories"] = loadAdvisories(enriched)
	}
	data["_triage_enabled"] = triageEnabled
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
