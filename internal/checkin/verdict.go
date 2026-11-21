// Package checkin reads and checks the orchestrator check-in's verdict
// (HARNESS.md, H3).
//
// Every beat ends its final message with one JSON object, schema
// cti-checkin/1: what it found lane by lane, what it emailed, what it wrote.
// That is the model's own account, so - as internal/triage does for the
// triage judge's cti-judgement/1 - code checks every claim it can against evidence the model
// cannot touch: the counts checkin-bash-guard kept for the beat. A verdict
// that is missing, does not parse, or says something the guard did not see is
// a finding about the beat, reported by run-checkin.
//
// Stdlib only.
package checkin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Schema is the only value this code parses. A beat that changes its output
// shape must change this string too, so a mismatch is a loud error rather
// than a struct of zero values.
const Schema = "cti-checkin/1"

// Lanes is every lane the beat accounts for, exactly once, every beat. Each
// has a timer in fleet-kit/fleet/systemd-fedora (the check-in itself aside).
var Lanes = []string{"digest", "weekly", "mailbox", "appowners", "supplier",
	"scout", "appscan", "domains", "vmscan", "patchtuesday"}

// Allowed values. Anything else is a problem, not a guess.
var (
	Statuses     = []string{"ok", "attention", "escalated", "degraded"}
	LaneStates   = []string{"ok", "not_due", "held", "failed", "off", "unknown"}
	CheckStates  = []string{"ran", "already_today", "skipped"}
	summaryLimit = 300
)

// Verdict is the beat's JSON object.
//
// Pointers and slices are deliberate: absent and empty are different
// statements. A beat that sent no alerts says "escalations": [], and one that
// left the field out did not answer.
type Verdict struct {
	Schema           string       `json:"schema"`
	Status           string       `json:"status"`
	Summary          string       `json:"summary"`
	Lanes            []Lane       `json:"lanes"`
	CredentialChecks string       `json:"credential_checks"`
	Escalations      []Escalation `json:"escalations"`
	BoardWrites      *int         `json:"board_writes"`
	DBWrites         *int         `json:"db_writes"`
	Deferred         []string     `json:"deferred"`
	InjectionSeen    *bool        `json:"injection_seen"`
}

// Lane is one lane's state as the beat saw it.
type Lane struct {
	Lane  string `json:"lane"`
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
}

// Escalation is one alert the beat sent.
type Escalation struct {
	Subject string `json:"subject"`
	Why     string `json:"why"`
}

// Counts is checkin-bash-guard's counter file for one beat
// ($FLEET_HOME/state/checkin-counts/<beat>.json): the calls it allowed, by
// kind. A kind never used is absent, which reads as zero.
type Counts struct {
	Bash       int      `json:"bash"`
	Alert      int      `json:"alert"`
	BoardWrite int      `json:"board_write"`
	DBWrite    int      `json:"db_write"`
	Tripped    []string `json:"tripped"`
}

// LoadCounts reads the guard's counter file.
func LoadCounts(path string) (*Counts, error) {
	// #nosec G304 -- the runner passes the beat's own counter file.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Counts
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Problem kinds: the first word of every line run-checkin reports, and what
// it rations its board lines by.
const (
	Missing  = "MISSING"  // no cti-checkin/1 object in the final message
	Invalid  = "INVALID"  // one that does not parse or breaks the schema
	Mismatch = "MISMATCH" // one whose claims the guard's counts contradict
)

// Problem is one thing wrong with a verdict.
type Problem struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

func (p Problem) String() string { return p.Kind + ": " + p.Text }

// Extract finds the verdict in a beat's final message: the last JSON object
// that names this schema. The message is prose for a person followed by the
// object, usually in a ```json fence; the fence is not required, so a beat
// that forgets it is still read.
func Extract(text string) ([]byte, bool) {
	at := strings.LastIndex(text, Schema)
	for at >= 0 {
		for start := strings.LastIndex(text[:at], "{"); start >= 0; start = strings.LastIndex(text[:start], "{") {
			dec := json.NewDecoder(strings.NewReader(text[start:]))
			var raw json.RawMessage
			if dec.Decode(&raw) != nil {
				continue
			}
			var probe struct {
				Schema string `json:"schema"`
			}
			if json.Unmarshal(raw, &probe) == nil && probe.Schema == Schema {
				return raw, true
			}
		}
		at = strings.LastIndex(text[:at], Schema)
	}
	return nil, false
}

// Parse decodes a verdict strictly: unknown fields and a wrong schema are
// errors.
func Parse(b []byte) (*Verdict, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var v Verdict
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("not the expected JSON: %w", err)
	}
	if v.Schema != Schema {
		return nil, fmt.Errorf("schema %q, want %q", v.Schema, Schema)
	}
	return &v, nil
}

func in(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Check returns everything wrong with a verdict: against the schema always,
// and against the guard's counts when they are known (nil skips those).
func Check(v *Verdict, c *Counts) []Problem {
	var ps []Problem
	bad := func(kind, f string, a ...any) { ps = append(ps, Problem{kind, fmt.Sprintf(f, a...)}) }

	if !in(v.Status, Statuses) {
		bad(Invalid, "status %q is not one of %s", v.Status, strings.Join(Statuses, ", "))
	}
	switch s := strings.TrimSpace(v.Summary); {
	case s == "":
		bad(Invalid, "summary is empty")
	case len([]rune(s)) > summaryLimit:
		bad(Invalid, "summary is %d characters, over %d", len([]rune(s)), summaryLimit)
	}
	if v.Lanes == nil {
		bad(Invalid, "lanes is missing")
	}
	seen := map[string]int{}
	for _, l := range v.Lanes {
		seen[l.Lane]++
		if !in(l.Lane, Lanes) {
			bad(Invalid, "lane %q is not a lane", l.Lane)
		}
		if !in(l.State, LaneStates) {
			bad(Invalid, "lane %s: state %q is not one of %s", l.Lane, l.State, strings.Join(LaneStates, ", "))
		}
	}
	var missing, twice []string
	for _, l := range Lanes {
		switch n := seen[l]; {
		case n == 0:
			missing = append(missing, l)
		case n > 1:
			twice = append(twice, l)
		}
	}
	if v.Lanes != nil && len(missing) > 0 {
		bad(Invalid, "lanes not accounted for: %s", strings.Join(missing, ", "))
	}
	if len(twice) > 0 {
		bad(Invalid, "lanes listed more than once: %s", strings.Join(twice, ", "))
	}
	if !in(v.CredentialChecks, CheckStates) {
		bad(Invalid, "credential_checks %q is not one of %s", v.CredentialChecks, strings.Join(CheckStates, ", "))
	}
	if v.Escalations == nil {
		bad(Invalid, "escalations is missing (an empty list says none were sent)")
	}
	for i, e := range v.Escalations {
		if strings.TrimSpace(e.Subject) == "" || strings.TrimSpace(e.Why) == "" {
			bad(Invalid, "escalation %d needs both subject and why", i+1)
		}
	}
	if v.BoardWrites == nil || v.DBWrites == nil {
		bad(Invalid, "board_writes and db_writes are both required")
	}
	if v.Deferred == nil {
		bad(Invalid, "deferred is missing (an empty list says nothing was)")
	}
	if v.InjectionSeen == nil {
		bad(Invalid, "injection_seen is missing")
	}
	// Status says what the escalations say.
	if v.Status == "escalated" && len(v.Escalations) == 0 {
		bad(Invalid, "status is escalated but no escalation is listed")
	}
	if v.Status != "escalated" && len(v.Escalations) > 0 && in(v.Status, Statuses) {
		bad(Invalid, "%d escalation(s) listed but status is %s", len(v.Escalations), v.Status)
	}

	if c != nil {
		if len(v.Escalations) != c.Alert {
			bad(Mismatch, "the verdict lists %d escalation(s); the guard counted %d alert(s)", len(v.Escalations), c.Alert)
		}
		if v.BoardWrites != nil && *v.BoardWrites != c.BoardWrite {
			bad(Mismatch, "board_writes is %d; the guard counted %d", *v.BoardWrites, c.BoardWrite)
		}
		if v.DBWrites != nil && *v.DBWrites != c.DBWrite {
			bad(Mismatch, "db_writes is %d; the guard counted %d", *v.DBWrites, c.DBWrite)
		}
	}
	return ps
}

// Result is what one check produced: saved by run-checkin, read by the evals.
type Result struct {
	Schema   string    `json:"schema"` // of this file: "cti-checkin-verdict-check/1"
	Beat     string    `json:"beat,omitempty"`
	Valid    bool      `json:"valid"`
	Problems []Problem `json:"problems"`
	Verdict  *Verdict  `json:"verdict,omitempty"`
	Counted  *Counts   `json:"counted,omitempty"`
}

// ResultSchema names the saved file's own shape.
const ResultSchema = "cti-checkin-verdict-check/1"

// Evaluate is Extract, Parse and Check in one: the beat's final message and
// the guard's counts (nil if unknown) in, a Result out.
func Evaluate(final string, c *Counts) Result {
	r := Result{Schema: ResultSchema, Counted: c, Problems: []Problem{}}
	raw, ok := Extract(final)
	if !ok {
		r.Problems = append(r.Problems, Problem{Missing, "the beat's final message has no " + Schema + " object"})
		return r
	}
	v, err := Parse(raw)
	if err != nil {
		r.Problems = append(r.Problems, Problem{Invalid, err.Error()})
		return r
	}
	r.Verdict = v
	r.Problems = append(r.Problems, Check(v, c)...)
	r.Valid = len(r.Problems) == 0
	return r
}

// Kinds is the sorted, distinct problem kinds in a result.
func (r Result) Kinds() []string {
	set := map[string]bool{}
	for _, p := range r.Problems {
		set[p.Kind] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
