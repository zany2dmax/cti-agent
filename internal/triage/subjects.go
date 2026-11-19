package triage

// THE READER'S ANSWER: WHAT AN ADVISORY IS ABOUT
//
// The reader is the first of two models (the triage redesign plan). It reads
// one advisory and nothing else - never our inventory, never a lookup result
// - and says which vendors, products, versions and ATT&CK techniques it
// concerns. It has no tools and never holds anything of ours, so a poisoned
// advisory cannot make it leak or do anything. It can make it name a wrong
// product or version, write misleading prose in the title, affected-versions
// or refusal text (which is why those are labelled as the reader's words),
// or refuse, which skips the product lookups but never the indicators or the
// advisory's own techniques.
//
// Code does not take its word for anything. VerifySubjects keeps a product,
// vendor or fixed version only if it is in the advisory as a whole word (so
// "1.0" is not found inside "131.0", nor "SQL" inside "MySQL"), keeps a quote
// only if it is in the advisory word for word, and marks a technique the
// advisory does not name as inferred. It checks against the text the reader
// was shown, fence markers removed, so no quote can carry a marker out. What survives goes into lookups, so it
// also has to be the right shape for one.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// SubjectsSchema is the only reader output this code parses.
//
// /2 added cves per item: an item that names a CVE is the CVE digest's, and
// triage sets it aside rather than judging it twice.
const SubjectsSchema = "cti-subjects/2"

// Caps on what one advisory can make code do.
const (
	maxSubjects      = 10
	maxQuotes        = 3
	maxTechniques    = 10
	maxSubjectFieldN = 120
	maxQuoteRunes    = 300
	minProductRunes  = 3
)

// tooCommon are words that pass every whole-word check and would turn a
// product lookup into a scan of the estate.
var tooCommon = map[string]bool{
	"the": true, "and": true, "for": true, "all": true, "any": true, "new": true,
	"web": true, "app": true, "apps": true, "api": true, "software": true, "server": true,
	"client": true, "agent": true, "service": true, "plugin": true, "update": true,
}

// Subject is one thing an advisory is about.
type Subject struct {
	Title      string   `json:"title"`
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	Affected   string   `json:"affected_versions"` // as the advisory states it, free text
	FixedIn    string   `json:"fixed_in"`          // the first fixed version, if the advisory gives one
	Techniques []string `json:"techniques"`
	CVEs       []string `json:"cves"`
	Quotes     []string `json:"quotes"`

	// Set by VerifySubjects, never by the model.
	Inferred []string `json:"inferred_techniques,omitempty"` // named by the reader, not by the advisory
}

// Subjects is the reader's whole answer.
type Subjects struct {
	Schema  string    `json:"schema"`
	Items   []Subject `json:"items"`
	Refusal *struct {
		Reason string `json:"reason"`
	} `json:"refusal"`

	// Set by VerifySubjects, never by the model: the items that name a CVE
	// found in the advisory. The CVE digest reports those (looked up in the
	// scanner, ticketed), so triage does not judge them again.
	CVEItems []Subject `json:"-"`
}

// SubjectViolation is one thing VerifySubjects removed, and why.
type SubjectViolation struct {
	Item   int    `json:"item"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (v SubjectViolation) String() string {
	return fmt.Sprintf("item %d %s: %s", v.Item, v.Field, v.Reason)
}

// ParseSubjects reads the reader's answer. The model may wrap the JSON in a
// fence or a sentence; only the outermost object is read, and its schema must
// match.
func ParseSubjects(b []byte) (*Subjects, error) {
	s := strings.TrimSpace(string(b))
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i < 0 || j <= i {
		return nil, errors.New("reader: no JSON object in the answer")
	}
	var out Subjects
	dec := json.NewDecoder(strings.NewReader(s[i : j+1]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("reader: answer is not %s: %v", SubjectsSchema, err)
	}
	if out.Schema != SubjectsSchema {
		return nil, fmt.Errorf("reader: schema %q, want %q", oneLine(out.Schema), SubjectsSchema)
	}
	return &out, nil
}

var (
	cveIDOnly       = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	fixedVersionRE  = regexp.MustCompile(`^\d+(\.\d+){0,4}$`)
	techniqueIDOnly = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

// VerifySubjects removes everything the advisory does not support, in place,
// and returns what it removed. body is the advisory text the reader was
// shown; extracted are the techniques code found in it.
func VerifySubjects(s *Subjects, body string, extracted []string) []SubjectViolation {
	var vs []SubjectViolation
	s.CVEItems = nil
	if s.Refusal != nil {
		s.Items = nil
		return nil
	}
	src := fold(stripMarkers(body))
	named := map[string]bool{}
	for _, t := range extracted {
		named[strings.ToUpper(t)] = true
	}
	in := func(text string) bool { return text != "" && strings.Contains(src, fold(text)) }
	word := func(text string) bool { return text != "" && wordIn(src, fold(text), false) }
	version := func(text string) bool { return text != "" && wordIn(src, fold(text), true) }

	if len(s.Items) > maxSubjects {
		vs = append(vs, SubjectViolation{maxSubjects, "items", fmt.Sprintf("%d items, only the first %d kept", len(s.Items), maxSubjects)})
		s.Items = s.Items[:maxSubjects]
	}
	kept := s.Items[:0]
	for i, it := range s.Items {
		drop := func(field, reason string) { vs = append(vs, SubjectViolation{i, field, reason}) }
		it.Title = clip(stripMarkers(it.Title))
		it.Affected = clip(stripMarkers(it.Affected))

		it.Product = clip(it.Product)
		switch {
		case it.Product == "":
		case runeCount(it.Product) < minProductRunes || tooCommon[strings.ToLower(it.Product)]:
			drop("product", "too short or too common to look up")
			it.Product = ""
		case !word(it.Product):
			drop("product", "not in the advisory as a whole word")
			it.Product = ""
		}
		it.Vendor = clip(it.Vendor)
		if it.Vendor != "" && !word(it.Vendor) {
			drop("vendor", "not in the advisory as a whole word")
			it.Vendor = ""
		}
		it.FixedIn = strings.TrimSpace(it.FixedIn)
		if it.FixedIn != "" && (!fixedVersionRE.MatchString(it.FixedIn) || !version(it.FixedIn)) {
			drop("fixed_in", "not a whole version number found in the advisory")
			it.FixedIn = ""
		}
		var quotes []string
		for _, q := range it.Quotes {
			if len(quotes) == maxQuotes {
				break
			}
			q = strings.TrimSpace(q)
			if runeCount(q) > maxQuoteRunes {
				drop("quote", fmt.Sprintf("longer than %d characters", maxQuoteRunes))
				continue
			}
			if in(q) {
				quotes = append(quotes, q)
			} else if q != "" {
				drop("quote", "not in the advisory word for word")
			}
		}
		it.Quotes = quotes
		var techs []string
		it.Inferred = nil
		seen := map[string]bool{}
		for _, t := range it.Techniques {
			t = strings.ToUpper(strings.TrimSpace(t))
			if !techniqueIDOnly.MatchString(t) || seen[t] {
				if t != "" && !seen[t] {
					drop("technique", fmt.Sprintf("%q is not an ATT&CK technique ID", oneLine(t)))
				}
				continue
			}
			if len(techs) == maxTechniques {
				break
			}
			seen[t] = true
			techs = append(techs, t)
			// A parent (T1566) is not named by its sub-technique (T1566.002):
			// wordIn does not find it followed by "." and a digit.
			if !named[t] && !version(t) {
				it.Inferred = append(it.Inferred, t)
			}
		}
		it.Techniques = techs
		var cves []string
		seenCVE := map[string]bool{}
		for _, c := range it.CVEs {
			c = strings.ToUpper(strings.TrimSpace(c))
			switch {
			case c == "" || seenCVE[c]:
			case !cveIDOnly.MatchString(c) || !version(c):
				drop("cve", fmt.Sprintf("%q is not a CVE ID found in the advisory", oneLine(c)))
			default:
				cves = append(cves, c)
			}
			seenCVE[c] = true
		}
		it.CVEs = cves
		if len(it.CVEs) > 0 {
			// The CVE digest's item: set aside, not judged again here.
			s.CVEItems = append(s.CVEItems, it)
			continue
		}
		if it.Product == "" && len(it.Techniques) == 0 {
			drop("item", "nothing left that a lookup could use")
			continue
		}
		kept = append(kept, it)
	}
	s.Items = kept
	return vs
}

// fold is the comparison form: lower case, every run of whitespace one space,
// so a quote that wrapped across lines in the mail still matches.
func fold(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), unicode.IsSpace), " ")
}

func clip(s string) string {
	s = oneLine(strings.TrimSpace(s))
	if r := []rune(s); len(r) > maxSubjectFieldN {
		s = string(r[:maxSubjectFieldN])
	}
	return s
}

func runeCount(s string) int { return len([]rune(s)) }

// wordIn reports whether needle occurs in hay as a whole word: no letter or
// digit on either side, and not followed by "." and a digit (so "131.0" is
// not found in "131.0.6778", nor "t1566" in "t1566.002"). With version, it
// may not be preceded by "." either ("6778.86" is not in "131.0.6778.86").
func wordIn(hay, needle string, version bool) bool {
	if needle == "" {
		return false
	}
	isWord := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	for from := 0; from <= len(hay)-len(needle); {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(needle)
		ok := true
		if start > 0 {
			prev := []rune(hay[:start])
			if p := prev[len(prev)-1]; isWord(p) || (version && p == '.') {
				ok = false
			}
		}
		if ok && end < len(hay) {
			next := []rune(hay[end:])
			if isWord(next[0]) || (next[0] == '.' && len(next) > 1 && unicode.IsDigit(next[1])) {
				ok = false
			}
		}
		if ok {
			return true
		}
		from = start + 1
	}
	return false
}
