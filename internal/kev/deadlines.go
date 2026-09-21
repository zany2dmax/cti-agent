// Package kev reports on CISA KEV remediation deadlines for vulnerabilities
// that are actually present in the environment.
//
// # WHY A DEADLINE REPORT AT ALL
//
// Sev5-Sev1 answers "what should we do first". It does not answer "what are we
// late on", and those are different conversations with different audiences.
// A deadline published by CISA under BOD 22-01 is a date somebody else set:
// far more durable in a patching argument than an internal opinion about
// severity, and the only line item in this whole system that a non-technical
// reader can act on without translation.
//
// # EVERYTHING HERE IS RESTRICTED TO PRESENT FINDINGS
//
// A deadline on a CVE we do not run is not an obligation. Counting those
// inflates the number, and the first time someone checks one and finds it
// irrelevant, the section stops being read - which costs more than it ever
// gained. Presence comes from the scanner, never from inference.
package kev

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Finding is the subset of an enriched finding this package needs. The
// enriched JSON carries far more; decoding only what is used means an upstream
// field addition cannot break this report.
type Finding struct {
	CVE        string  `json:"cve"`
	Status     string  `json:"status"`
	HostCount  int     `json:"host_count"`
	QIDs       string  `json:"qids"`
	Priority   string  `json:"priority"`
	KEV        int     `json:"kev"`
	KEVDue     string  `json:"kev_due"`
	KEVAdded   string  `json:"kev_added"`
	KEVAction  string  `json:"required_action"`
	Ransomware string  `json:"ransomware"`
	EPSS       float64 `json:"epss"`
	CVSS       float64 `json:"cvss"`
	Hosts      string  `json:"sample_hosts"`
	Rationale  string  `json:"rationale"`
}

// Enriched is the enrich lane's output file.
type Enriched struct {
	Generated  string            `json:"generated"`
	SourceMeta map[string]string `json:"source_meta"`
	Total      int               `json:"total"`
	Degraded   []string          `json:"degraded"`
	Findings   []Finding         `json:"findings"`
}

// Present reports whether the scanner actually found this CVE here. Status
// alone is not enough: PRESENT with zero hosts is a provider quirk, not an
// exposure.
func (f Finding) Present() bool {
	return strings.EqualFold(f.Status, "PRESENT") && f.HostCount > 0
}

// DaysLeft returns days until the deadline, negative when overdue, and false
// when there is no usable date. "No deadline" and "due today" are opposite
// facts and must not collapse into the same zero.
func (f Finding) DaysLeft(now time.Time) (int, bool) {
	raw := strings.TrimSpace(f.KEVDue)
	if len(raw) < 10 {
		return 0, false
	}
	due, err := time.Parse("2006-01-02", raw[:10])
	if err != nil {
		return 0, false
	}
	// Compare dates, not instants: a deadline is a calendar day, and using
	// wall-clock time would make "due today" flip to overdue at noon.
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return int(due.Sub(today).Hours() / 24), true
}

func (f Finding) IsRansomware() bool {
	return strings.EqualFold(strings.TrimSpace(f.Ransomware), "known")
}

// Report is the deadline picture at one moment.
type Report struct {
	Now        time.Time
	Overdue    []Dated // deadline passed, present here
	DueSoon    []Dated // deadline within the horizon, present here
	Later      []Dated // present here, deadline further out
	NotHere    int     // KEV with a deadline that the scanner did not find
	Unverified int     // KEV with a deadline whose coverage is UNKNOWN
	Horizon    int
}

// Dated pairs a finding with its computed deadline distance.
type Dated struct {
	Finding
	Days int // negative means overdue
}

// Analyze splits findings by deadline. Horizon is the "due soon" window in
// days; 14 is a reasonable default for a monthly patch cycle.
func Analyze(e *Enriched, now time.Time, horizon int) *Report {
	r := &Report{Now: now, Horizon: horizon}
	for _, f := range e.Findings {
		days, ok := f.DaysLeft(now)
		if !ok {
			continue // no deadline to report on
		}
		if !f.Present() {
			// Tracked separately rather than dropped: "12 KEV deadlines we
			// are not exposed to" is reassuring context, and its absence
			// invites the question of whether they were considered.
			if strings.EqualFold(f.Status, "UNKNOWN") {
				r.Unverified++
			} else {
				r.NotHere++
			}
			continue
		}
		d := Dated{Finding: f, Days: days}
		switch {
		case days < 0:
			r.Overdue = append(r.Overdue, d)
		case days <= horizon:
			r.DueSoon = append(r.DueSoon, d)
		default:
			r.Later = append(r.Later, d)
		}
	}
	// Worst first within each band, then by blast radius. Sorting by host
	// count alone would bury a deadline passed a month ago behind one that
	// lapsed yesterday on more machines.
	byUrgency := func(s []Dated) {
		sort.SliceStable(s, func(i, j int) bool {
			if s[i].Days != s[j].Days {
				return s[i].Days < s[j].Days
			}
			return s[i].HostCount > s[j].HostCount
		})
	}
	byUrgency(r.Overdue)
	byUrgency(r.DueSoon)
	byUrgency(r.Later)
	return r
}

// WorstOverdueDays is how far past the earliest missed deadline we are.
func (r *Report) WorstOverdueDays() int {
	if len(r.Overdue) == 0 {
		return 0
	}
	return -r.Overdue[0].Days
}

// RansomwareCount counts present findings associated with ransomware
// campaigns, across every band. CISA flags these specifically, and it is the
// one attribute that reliably changes how urgently a business responds.
func (r *Report) RansomwareCount() int {
	n := 0
	for _, s := range [][]Dated{r.Overdue, r.DueSoon, r.Later} {
		for _, d := range s {
			if d.IsRansomware() {
				n++
			}
		}
	}
	return n
}

// Clean reports whether there is nothing to act on. Used to decide whether
// the report is worth including in a digest at all - a section that says
// "nothing overdue" every day teaches people to skip it.
func (r *Report) Clean() bool {
	return len(r.Overdue) == 0 && len(r.DueSoon) == 0
}

// Load reads an enriched JSON file.
func Load(path string) (*Enriched, error) {
	// #nosec G304 -- path is an operator-supplied --enriched flag or a path
	// derived from $FLEET_HOME, both of which are trusted to the same degree
	// as the binary itself. There is no untrusted input on this path: a
	// service that cannot be told which file to read is not configurable.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kev: reading %s: %w", path, err)
	}
	var e Enriched
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("kev: %s is not valid enriched JSON: %w", path, err)
	}
	return &e, nil
}

// Markdown renders the report. Deliberately terse: this goes into an email
// alongside the digest, and length is the enemy of both.
func (r *Report) Markdown(showHosts bool) string {
	var b strings.Builder
	b.WriteString("## CISA KEV remediation deadlines\n\n")

	if r.Clean() {
		fmt.Fprintf(&b, 
			"Nothing overdue and nothing due within %dd.\n\n", r.Horizon)
	}

	if n := len(r.Overdue); n > 0 {
		fmt.Fprintf(&b, "### %d OVERDUE — deadline already passed\n\n", n)
		b.WriteString(r.table(r.Overdue, showHosts))
		b.WriteString("\n")
	}
	if n := len(r.DueSoon); n > 0 {
		fmt.Fprintf(&b, "### %d due within %dd\n\n", n, r.Horizon)
		b.WriteString(r.table(r.DueSoon, showHosts))
		b.WriteString("\n")
	}

	b.WriteString("| | |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Overdue, present here | %d |\n", len(r.Overdue))
	fmt.Fprintf(&b, "| Due within %dd, present here | %d |\n", r.Horizon, len(r.DueSoon))
	fmt.Fprintf(&b, "| Later deadline, present here | %d |\n", len(r.Later))
	fmt.Fprintf(&b, "| Ransomware-associated, present here | %d |\n", r.RansomwareCount())
	fmt.Fprintf(&b, "| KEV deadlines not detected here | %d |\n", r.NotHere)
	fmt.Fprintf(&b, "| KEV deadlines, coverage UNVERIFIED | %d |\n", r.Unverified)

	if r.Unverified > 0 {
		fmt.Fprintf(&b, 
			"\n> %d KEV %s a published deadline could not be checked against the "+
				"scanner. That is not a clean result — it means we did not look.\n",
			r.Unverified, plural(r.Unverified, "vulnerability with", "vulnerabilities with"))
	}
	return b.String()
}

func (r *Report) table(rows []Dated, showHosts bool) string {
	var b strings.Builder
	b.WriteString("| CVE | Due | Days | Hosts | Sev | QIDs |")
	if showHosts {
		b.WriteString(" Sample hosts |")
	}
	b.WriteString("\n|---|---|---:|---:|---|---|")
	if showHosts {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, d := range rows {
		days := fmt.Sprintf("%+d", d.Days)
		if d.Days == 0 {
			days = "today"
		}
		flag := d.Priority
		if d.IsRansomware() {
			flag += " ⚠ransomware"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s |",
			d.CVE, d.KEVDue, days, d.HostCount, flag, orDash(d.QIDs))
		if showHosts {
			fmt.Fprintf(&b, " %s |", orDash(d.Hosts))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
