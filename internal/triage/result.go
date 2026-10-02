package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ─── what the agent returns ─────────────────────────────────────────────────

// Schema is the only value this code will parse. A future agent that changes
// its output shape must change this string too, so a mismatch is a loud error
// rather than a struct full of zero values.
const Schema = "cti-triage/1"

// Result is the agent's JSON object.
//
// Pointer and slice fields are deliberate: `null` and `[]` and absent are
// different statements, and collapsing them loses the distinction between "the
// agent said there were none" and "the agent did not answer".
type Result struct {
	Schema           string   `json:"schema"`
	MessageID        string   `json:"message_id"`
	ItemCount        int      `json:"item_count"`
	ItemCountStated  *int     `json:"item_count_stated"`
	Items            []Item   `json:"items"`
	NotInExtraction  []string `json:"indicators_not_in_extraction"`
	NotRealIndicator []string `json:"extraction_not_really_indicators"`
	Notes            []string `json:"notes"`
	InjectionAttempt bool     `json:"injection_attempt"`
	Confidence       string   `json:"confidence"`
	Refused          bool     `json:"refused"`
}

// Item is one piece of intelligence inside an advisory.
type Item struct {
	Title           string   `json:"title"`
	Source          string   `json:"source"`
	Date            string   `json:"date"`
	Link            *string  `json:"link"`
	CVEs            []string `json:"cves"`
	Techniques      []string `json:"techniques"`
	Indicators      []string `json:"indicators"`
	Products        []string `json:"products"`
	Summary         string   `json:"summary"`
	WhyItMightMatter *string `json:"why_it_might_matter"`
	Relevance       string   `json:"relevance"`
	RelevanceReason string   `json:"relevance_reason"`
	SuggestedChecks []string `json:"suggested_checks"`
	Evidence        []string `json:"evidence"`
}

// Relevance values. Anything else is replaced with RelevanceUnknown, because a
// relevance this code does not recognise cannot be sorted, coloured or
// reasoned about, and silently treating it as "unlikely" would be the worst
// available guess.
const (
	RelevanceLikely   = "likely"
	RelevancePossible = "possible"
	RelevanceUnlikely = "unlikely"
	RelevanceUnknown  = "unknown"
)

// rank orders the digest: the things a person should look at first come first.
// Unknown sorts above unlikely because "we could not tell" deserves more of a
// reader's attention than "we checked and it does not apply".
func rank(relevance string) int {
	switch relevance {
	case RelevanceLikely:
		return 0
	case RelevancePossible:
		return 1
	case RelevanceUnknown:
		return 2
	default:
		return 3
	}
}

// ─── verification ───────────────────────────────────────────────────────────

// Violation is one thing the agent got wrong, kept so it can be reported
// rather than quietly corrected.
//
// Quiet correction is the failure mode this whole package exists to avoid. If
// the model starts fabricating indicators, the digest must say so - otherwise
// the only visible symptom is that the output looks slightly better than the
// input deserved, which nobody notices.
type Violation struct {
	Kind  string // "fabricated", "dropped", "bad-relevance", "count-mismatch", "bad-schema"
	Item  string // the item title, or "" when it is about the whole result
	Field string
	Value string
	Why   string
}

func (v Violation) String() string {
	where := "result"
	if v.Item != "" {
		where = fmt.Sprintf("item %q", v.Item)
	}
	if v.Value != "" {
		return fmt.Sprintf("%s: %s.%s = %q - %s", where, v.Kind, v.Field, v.Value, v.Why)
	}
	return fmt.Sprintf("%s: %s %s - %s", where, v.Kind, v.Field, v.Why)
}

// Parse decodes the agent's output.
//
// Strict about unknown fields: an agent that invented a field is an agent
// whose output shape we no longer understand, and the right response is to say
// so rather than to read the fields we recognise and hope.
func Parse(b []byte) (*Result, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	var r Result
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("triage output is not the expected JSON: %w", err)
	}
	if r.Schema != Schema {
		return nil, fmt.Errorf("triage output has schema %q, want %q", r.Schema, Schema)
	}
	return &r, nil
}

// Verify enforces, in code, every promise made to the agent in its standing
// instructions.
//
// THIS IS NOT A FORMALITY. The instructions tell the agent that code checks
// its work; that sentence is load-bearing, and until this function existed it
// was false. Three specific guarantees:
//
//  1. COPIED, NOT COMPOSED. Every CVE, technique, indicator and quote must
//     appear character for character in the source. Anything that does not is
//     removed and recorded. A fabricated indicator is not a cosmetic problem -
//     it is how a hallucinated domain ends up on a blocklist.
//
//  2. NOTHING DROPPED. Anything the deterministic extractor found that the
//     agent did not mention is added back at the result level. The agent may
//     not shrink the input, and an omission is invisible downstream.
//
//  3. RELEVANCE IS GATED ON THE PROFILE. When the deployed ORG-PROFILE is
//     missing or still the template, every relevance becomes "unknown" no
//     matter what the agent said. The instructions ask for this; depending on
//     the model to comply with it is exactly the kind of trust this fleet does
//     not extend to anything, including itself.
//
// src is the message body as it was given to the agent. Verify mutates r.
func Verify(r *Result, src string, e Extraction, profile ProfileState) []Violation {
	var v []Violation

	// Case-insensitive containment. Advisories are inconsistent about the case
	// of CVE and technique identifiers, and rejecting "cve-2026-1234" as
	// fabricated when the body says "CVE-2026-1234" would be a false accusation
	// that trains the reader to ignore these.
	lower := strings.ToLower(src)
	present := func(s string) bool {
		return strings.Contains(lower, strings.ToLower(strings.TrimSpace(s)))
	}

	for i := range r.Items {
		it := &r.Items[i]

		for _, f := range []struct {
			name string
			list *[]string
		}{
			{"cves", &it.CVEs},
			{"techniques", &it.Techniques},
			{"indicators", &it.Indicators},
			{"evidence", &it.Evidence},
		} {
			kept := make([]string, 0, len(*f.list))
			for _, s := range *f.list {
				if s == "" {
					continue
				}
				if present(s) {
					kept = append(kept, s)
					continue
				}
				v = append(v, Violation{
					Kind: "fabricated", Item: it.Title, Field: f.name, Value: s,
					Why: "does not appear in the source text",
				})
			}
			*f.list = kept
		}

		switch it.Relevance {
		case RelevanceLikely, RelevancePossible, RelevanceUnlikely, RelevanceUnknown:
		default:
			v = append(v, Violation{
				Kind: "bad-relevance", Item: it.Title, Field: "relevance", Value: it.Relevance,
				Why: "not one of likely/possible/unlikely/unknown",
			})
			it.Relevance = RelevanceUnknown
		}

		// The profile gate. Applied after the enum check so a bad value cannot
		// survive by being overwritten with something else bad.
		if !profile.Usable() && it.Relevance != RelevanceUnknown {
			v = append(v, Violation{
				Kind: "bad-relevance", Item: it.Title, Field: "relevance", Value: it.Relevance,
				Why: "the deployed ORG-PROFILE is " + profile.String() +
					", so relevance cannot be judged - forced to unknown",
			})
			it.Relevance = RelevanceUnknown
			it.RelevanceReason = "no usable organisation profile on this host (" +
				profile.String() + ")"
		}
	}

	// Promise 2. Compared against the union of what every item claimed, not
	// per item: the agent is free to attribute an indicator to whichever item
	// it belongs to, and only a disappearance matters.
	for _, d := range []struct {
		name  string
		found []string
		saw   func(Item) []string
	}{
		{"cves", e.CVEs, func(i Item) []string { return i.CVEs }},
		{"techniques", e.Techniques, func(i Item) []string { return i.Techniques }},
		{"indicators", e.Indicators, func(i Item) []string { return i.Indicators }},
	} {
		seen := map[string]bool{}
		for _, it := range r.Items {
			for _, s := range d.saw(it) {
				seen[strings.ToLower(s)] = true
			}
		}
		for _, s := range d.found {
			if seen[strings.ToLower(s)] {
				continue
			}
			v = append(v, Violation{
				Kind: "dropped", Field: d.name, Value: s,
				Why: "the extractor found it and the agent did not mention it - " +
					"reported here instead",
			})
		}
	}

	if r.ItemCount != len(r.Items) {
		v = append(v, Violation{
			Kind: "count-mismatch", Field: "item_count",
			Value: fmt.Sprintf("%d", r.ItemCount),
			Why:   fmt.Sprintf("but there are %d items", len(r.Items)),
		})
		r.ItemCount = len(r.Items)
	}

	switch r.Confidence {
	case "high", "medium", "low":
	default:
		v = append(v, Violation{
			Kind: "bad-schema", Field: "confidence", Value: r.Confidence,
			Why: "not one of high/medium/low",
		})
		r.Confidence = "low"
	}

	sortItems(r.Items)
	return v
}

// Dropped returns the values the agent omitted, by field, so a caller can
// report them without re-walking the violations.
func Dropped(vs []Violation) map[string][]string {
	out := map[string][]string{}
	for _, v := range vs {
		if v.Kind == "dropped" {
			out[v.Field] = append(out[v.Field], v.Value)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// Fabricated returns the values the agent produced that are not in the source.
func Fabricated(vs []Violation) []Violation {
	var out []Violation
	for _, v := range vs {
		if v.Kind == "fabricated" {
			out = append(out, v)
		}
	}
	return out
}

// sortItems puts the digest in the order a person should read it: most
// relevant first, then by title so the ordering is stable across runs and a
// diff between two days means something.
func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		if a, b := rank(items[i].Relevance), rank(items[j].Relevance); a != b {
			return a < b
		}
		return items[i].Title < items[j].Title
	})
}
