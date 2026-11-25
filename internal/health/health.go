// Package health is the lane health contract: every lane writes a report of
// what it should have covered, what it did, and each gap, so the check-in can
// tell a gap somebody chose from one nobody noticed.
//
// THE THREE LAYERS. The contract (this package, the schema, how the check-in
// and the doctor read reports) is the fleet's. What a lane covers - its
// expected and covered subjects, its gap kinds - is the lane's, whoever wrote
// it. What a given fleet chose to leave uncovered is that organization's: its
// org pack's expected-gaps.txt, installed as $FLEET_CODE/share/expected-gaps.txt
// (docs/org-pack.md). A gap that matches a declaration is "expected", with the
// declaration's reason; every other gap is an accident until somebody says
// otherwise.
//
// A lane builds a Report with its subjects and gaps, calls Apply with the
// declarations, and Write: reports/health/<lane>.json, atomically, 0600.
// fleet-health (cmd/fleet-health) reads the reports for run-checkin and hands
// the beat only what changed since its last beat.
package health

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/zany2dmax/cti-agent/internal/layout"
)

// Schema is the report format's name and version.
const Schema = "cti-lane-health/1"

// Report is one lane's health, as of one run.
type Report struct {
	Schema    string    `json:"schema"`
	Lane      string    `json:"lane"`
	Generated time.Time `json:"generated"`
	// WindowHours is how far back the lane looked, 0 when the report is a
	// snapshot rather than a window.
	WindowHours int `json:"windowHours,omitempty"`
	// Of and Covered: how many subjects the lane should have covered (every
	// web app, every domain, every feed) and how many it did. Covered is Of
	// minus the gaps, expected or not.
	Of      int   `json:"of"`
	Covered int   `json:"covered"`
	Gaps    []Gap `json:"gaps"`
	// Error is set when the lane could not work out its health at all (its
	// source was unreachable): the report is then the error, not a clean bill.
	Error string `json:"error,omitempty"`
	// Unused lists this lane's declarations that matched no gap: a stale
	// exception, or one naming something that no longer exists.
	Unused []string `json:"unusedDeclarations,omitempty"`
	// Expiring lists this lane's declarations whose until= date is within
	// ExpiryWarning, so they are renewed or dropped on purpose.
	Expiring []string `json:"expiringDeclarations,omitempty"`
}

// Gap is one subject the lane did not cover, or covered badly.
type Gap struct {
	Subject string `json:"subject"`
	// ID is the subject's identifier at its source, when it has one (a web
	// app's id); a declaration may name it as id:<ID>.
	ID     string `json:"id,omitempty"`
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
	// Expected is true when a declaration covers this gap, and Why is the
	// declaration's reason. An expired declaration covers nothing.
	Expected bool   `json:"expected"`
	Why      string `json:"why,omitempty"`
}

// Key is how a gap is recognised from one report to the next: by its
// source id when it has one, so two subjects that share a name (or a
// look-alike of one) never share a key, else by its name.
func (g Gap) Key() string {
	if id := strings.TrimSpace(g.ID); id != "" {
		return g.Kind + "|id:" + id
	}
	return g.Kind + "|" + subjectKey(g.Subject)
}

// Unexpected is the report's gaps that no declaration covers.
func (r Report) Unexpected() []Gap {
	var out []Gap
	for _, g := range r.Gaps {
		if !g.Expected {
			out = append(out, g)
		}
	}
	return out
}

// New is an empty report for lane, as of now.
func New(lane string, now time.Time) Report {
	return Report{Schema: Schema, Lane: lane, Generated: now.UTC(), Gaps: []Gap{}}
}

// Add records a gap. Subject and detail are made one line and bounded: they
// often come from outside the fleet (an application's name in the scanner).
func (r *Report) Add(subject, id, kind, detail string) {
	r.Gaps = append(r.Gaps, Gap{Subject: Clean(subject, 160), ID: Clean(id, 64), Kind: kind, Detail: Clean(detail, 300)})
}

// Clean is s as one line of printable text, at most n runes. Controls and
// line breaks become spaces; invisible format characters (zero-width, bidi
// overrides, the tag characters that hide text from a reader but not from a
// model) are dropped. It runs where a report is written AND where it is read
// for the check-in, since a report file is only as clean as whoever wrote it.
func Clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.Is(unicode.Cf, r), r >= 0xe0000 && r <= 0xe007f:
			return -1
		case r == ' ', unicode.IsGraphic(r):
			return r
		}
		return ' '
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if rs := []rune(s); len(rs) > n {
		s = string(rs[:n-1]) + "…"
	}
	return s
}

// subjectKey compares names: whitespace collapsed and ASCII case folded only.
// Full Unicode folding would let a look-alike (the Kelvin sign for "k")
// match a declared name.
func subjectKey(s string) string {
	b := []byte(strings.Join(strings.Fields(s), " "))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// ─── declarations ───────────────────────────────────────────────────────────

// Declaration is one line of expected-gaps.txt:
//
//	lane | subject | kind | reason | until=YYYY-MM-DD
//
// subject is a name, or id:<ID>; kind is a gap kind or * for any; until= is
// optional.
type Declaration struct {
	Lane, Subject, Kind, Reason string
	Until                       time.Time // zero: no expiry
	Line                        int
}

func (d Declaration) String() string {
	s := fmt.Sprintf("%s | %s | %s", d.Lane, d.Subject, d.Kind)
	if !d.Until.IsZero() {
		s += " | until=" + d.Until.Format("2006-01-02")
	}
	return s
}

var (
	laneRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	kindRE = regexp.MustCompile(`^(\*|[a-z][a-z0-9_]{0,39})$`)
)

// ExpiryWarning is how long before its until= date a declaration is listed as
// expiring.
const ExpiryWarning = 7 * 24 * time.Hour

// DefaultDeclarations is where the installer puts the org pack's file.
func DefaultDeclarations() string { return filepath.Join(layout.CodeDir, "share", "expected-gaps.txt") }

// ParseDeclarations reads expected-gaps.txt. Every line must be valid: a
// malformed declaration is an error, never skipped, since a skipped one
// would turn a chosen gap into an accident (or the reverse) silently.
func ParseDeclarations(r io.Reader) ([]Declaration, error) {
	var out []Declaration
	var bad []string
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if len(f) < 4 || len(f) > 5 {
			bad = append(bad, fmt.Sprintf("line %d: want lane | subject | kind | reason [| until=YYYY-MM-DD]", n))
			continue
		}
		d := Declaration{Lane: f[0], Subject: Clean(f[1], 160), Kind: f[2], Reason: Clean(f[3], 300), Line: n}
		switch {
		case !laneRE.MatchString(d.Lane):
			bad = append(bad, fmt.Sprintf("line %d: %q is not a lane name", n, d.Lane))
			continue
		case d.Subject == "":
			bad = append(bad, fmt.Sprintf("line %d: no subject", n))
			continue
		case !kindRE.MatchString(d.Kind):
			bad = append(bad, fmt.Sprintf("line %d: %q is not a gap kind (or *)", n, d.Kind))
			continue
		case d.Reason == "":
			bad = append(bad, fmt.Sprintf("line %d: no reason - a gap by design says why", n))
			continue
		}
		if len(f) == 5 {
			v, ok := strings.CutPrefix(f[4], "until=")
			t, err := time.Parse("2006-01-02", v)
			if !ok || err != nil {
				bad = append(bad, fmt.Sprintf("line %d: %q is not until=YYYY-MM-DD", n, f[4]))
				continue
			}
			d.Until = t
		}
		out = append(out, d)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("expected-gaps.txt: %s", strings.Join(bad, "; "))
	}
	return out, nil
}

// LoadDeclarations reads the file at path; a missing file is no declarations.
func LoadDeclarations(path string) ([]Declaration, error) {
	f, err := os.Open(path) // #nosec G304 -- the installed org pack file
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParseDeclarations(f)
}

func (d Declaration) matches(g Gap) bool {
	if d.Kind != "*" && d.Kind != g.Kind {
		return false
	}
	if id, ok := strings.CutPrefix(d.Subject, "id:"); ok {
		return g.ID != "" && strings.TrimSpace(id) == g.ID
	}
	return subjectKey(d.Subject) == subjectKey(g.Subject)
}

// Apply marks each gap a current declaration of this lane covers as
// expected, with its reason, and lists the lane's declarations that matched
// nothing and those about to expire. An expired declaration covers nothing:
// the gap is an accident again, and says the exception lapsed.
func (r *Report) Apply(decls []Declaration, now time.Time) {
	used := map[int]bool{}
	// A name declaration that matches two different subjects (two apps
	// given one name, or a look-alike created to borrow an exception)
	// covers neither: it is reported, and id:<ID> is the fix.
	ambiguous := map[int]bool{}
	for _, d := range decls {
		if d.Lane != r.Lane || strings.HasPrefix(d.Subject, "id:") {
			continue
		}
		ids := map[string]bool{}
		for _, g := range r.Gaps {
			if d.matches(g) {
				ids[g.ID+"|"+g.Subject] = true
			}
		}
		if len(ids) > 1 {
			ambiguous[d.Line] = true
		}
	}
	for i := range r.Gaps {
		for _, d := range decls {
			if d.Lane != r.Lane || ambiguous[d.Line] || !d.matches(r.Gaps[i]) {
				continue
			}
			used[d.Line] = true
			if !d.Until.IsZero() && now.After(d.Until.Add(24*time.Hour)) {
				r.Gaps[i].Why = "declared expected until " + d.Until.Format("2006-01-02") + ", which has passed"
				continue
			}
			r.Gaps[i].Expected, r.Gaps[i].Why = true, d.Reason
			break
		}
	}
	for _, d := range decls {
		if d.Lane != r.Lane {
			continue
		}
		switch {
		case ambiguous[d.Line]:
			r.Unused = append(r.Unused, d.String()+" (matches more than one subject, so it covers none: name it by id:)")
		case !used[d.Line]:
			r.Unused = append(r.Unused, d.String())
		}
		if !d.Until.IsZero() && !now.After(d.Until.Add(24*time.Hour)) && d.Until.Sub(now) < ExpiryWarning {
			r.Expiring = append(r.Expiring, d.String())
		}
	}
	sort.Strings(r.Unused)
	sort.Strings(r.Expiring)
}

// ─── writing and reading ────────────────────────────────────────────────────

// Path is the lane's report file under the fleet's home.
func Path(home, lane string) string { return filepath.Join(home, "reports", "health", lane+".json") }

// Write writes the report to path, 0600, atomically (a reader never sees half
// of one), creating the directory 0700.
func Write(path string, r Report) error {
	if r.Covered == 0 && r.Of > 0 {
		r.Covered = r.Of - len(r.Gaps)
		if r.Covered < 0 {
			r.Covered = 0
		}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".health-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Read reads one report, checking its schema.
func Read(path string) (Report, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the fleet's own reports directory
	if err != nil {
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("%s is not a health report: %w", filepath.Base(path), err)
	}
	if r.Schema != Schema {
		return Report{}, fmt.Errorf("%s has schema %q, not %s", filepath.Base(path), r.Schema, Schema)
	}
	return r, nil
}
