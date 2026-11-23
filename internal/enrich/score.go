package enrich

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/pyfmt"
)

// SevOrder is the severity bands, most urgent first. internal/brief mirrors it for
// rendering, and fleet-db migrates stored values to match.
var SevOrder = []string{"Sev5", "Sev4", "Sev3", "Sev2", "Sev1"}

var isoDate = regexp.MustCompile(`^(\d{4})-(\d{1,2})-(\d{1,2})$`)

// KEVDaysLeft is the days until the CISA KEV remediation deadline; negative
// means overdue. nil when there is no date to compare, rather than zero: "no
// deadline" and "due today" are opposite facts. A malformed date is nil too,
// so one bad catalog entry cannot stop enrichment for every other finding.
func KEVDaysLeft(due *string, today time.Time) *int {
	if due == nil {
		return nil
	}
	raw := strings.TrimSpace(*due)
	if raw == "" {
		return nil
	}
	if r := []rune(raw); len(r) > 10 {
		raw = string(r[:10])
	}
	m := isoDate.FindStringSubmatch(raw)
	if m == nil {
		return nil
	}
	y, _ := strconv.Atoi(m[1])
	mo, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[3])
	t := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC)
	if y < 1 || t.Year() != y || int(t.Month()) != mo || t.Day() != d {
		return nil // 2026-13-45 is not a date, not March of next year
	}
	ty, tm, td := today.Date()
	// Whole days by Unix time, not Duration, which cannot span 292 years.
	n := int((t.Unix() - time.Date(ty, tm, td, 0, 0, 0, 0, time.UTC).Unix()) / 86400)
	return &n
}

// scoreInput is what Prioritize reads from a finding.
type scoreInput struct {
	Status     string
	HostCount  int
	KEV        bool
	EPSS       float64
	CVSS       json.Number // "" when unknown
	KEVDue     *string
	Ransomware *string
}

func (s scoreInput) present() bool { return s.Status == "PRESENT" && s.HostCount > 0 }

// knownRansomware is the catalog's "Known" in any case. Nothing else counts,
// not even "Known " with a space.
func knownRansomware(r *string) bool { return r != nil && strings.ToLower(*r) == "known" }

// Prioritize combines exploitability with presence, on a Sev5-Sev1 scale,
// and says why.
//
// The whole point: a 10.0 CVSS on software we do not run is noise, and a 6.5
// that is being actively exploited on 300 of our hosts is an emergency. CVSS
// alone gets that backwards, which is why it is the tiebreaker and not the
// driver.
//
//	Sev5 - PRESENT and actively exploited (KEV or EPSS >= 10%)  -> today
//	Sev4 - PRESENT, not known to be exploited                   -> this patch cycle
//	Sev3 - exploited (KEV or EPSS >= 50%) AND coverage UNKNOWN  -> resolve coverage now
//	Sev2 - exploited but not present, or UNKNOWN with CVSS >= 9 -> verify coverage
//	Sev1 - everything else                                      -> awareness
//
// It is not P1-P4: that is the incident scale here, and a CTI digest
// labelled "P1" reads as a live incident. Sev5 is the most urgent.
//
// Sev4 above Sev3 is a judgement call: "we definitely have it, nobody is
// exploiting it" is bounded, assignable work, while an unverified finding
// may not affect us at all. What Sev3 must never be is the noise floor: an
// exploited CVE the scanner could not check means nobody looked. And
// presence alone earns Sev4 regardless of CVSS: a 5.5 on 186 hosts is a real
// patching obligation.
//
// The KEV deadline changes the wording, never the band: it is an obligation
// about a risk, not a change to it. It is stated only for a finding that is
// present, because "overdue" about software we do not run teaches people to
// discount the word.
func prioritize(s scoreInput, today time.Time) (band, why string, days *int) {
	present := s.present()
	unknown := s.Status == "UNKNOWN"
	cvss := numberValue(s.CVSS)
	hot := s.KEV || s.EPSS >= 0.10
	veryHot := s.KEV || s.EPSS >= 0.50
	days = KEVDaysLeft(s.KEVDue, today)

	var w []string
	if s.KEV {
		due := ""
		if s.KEVDue != nil {
			due = *s.KEVDue
		}
		switch {
		case days != nil && present && *days < 0:
			w = append(w, fmt.Sprintf("CISA KEV deadline PASSED %dd ago (%s)", -*days, due))
		case days != nil && present && *days == 0:
			w = append(w, fmt.Sprintf("CISA KEV deadline is TODAY (%s)", due))
		case days != nil && present && *days <= 14:
			w = append(w, fmt.Sprintf("CISA KEV due in %dd (%s)", *days, due))
		case days != nil && present:
			w = append(w, "on CISA KEV, due "+due)
		case days != nil:
			w = append(w, fmt.Sprintf("on CISA KEV (due %s, not detected here)", due))
		default:
			w = append(w, "on CISA KEV")
		}
	}
	switch {
	case s.EPSS >= 0.50:
		w = append(w, "EPSS "+percent(s.EPSS)+" - exploitation likely")
	case s.EPSS >= 0.10:
		w = append(w, "EPSS "+percent(s.EPSS)+" - elevated")
	}
	if cvss != 0 {
		w = append(w, "CVSS "+pyNumber(s.CVSS))
	}
	switch {
	case present:
		w = append(w, fmt.Sprintf("PRESENT on %d host(s)", s.HostCount))
	case s.Status == "NOT_PRESENT":
		w = append(w, "not detected in Qualys")
	case unknown:
		w = append(w, "no Qualys QID mapping - coverage unverified")
	}
	if knownRansomware(s.Ransomware) {
		w = append(w, "used in ransomware campaigns")
	}

	switch {
	case present && hot:
		band = "Sev5"
	case present:
		band = "Sev4"
	case unknown && veryHot:
		band = "Sev3"
	case hot || (unknown && cvss >= 9.0):
		// UNKNOWN means we did not look, not that we are clean.
		band = "Sev2"
	default:
		band = "Sev1"
	}
	why = strings.Join(w, "; ")
	if why == "" {
		why = "no enrichment data available"
	}
	return band, why, days
}

// KEVSummary is the deadline rollup, over findings that are actually in the
// estate: a deadline on a CVE we do not run is not an obligation, and
// counting those makes the whole section stop being read.
type KEVSummary struct {
	Overdue           int      `json:"overdue"`
	DueWithin14d      int      `json:"due_within_14d"`
	WorstOverdueDays  int      `json:"worst_overdue_days"`
	RansomwarePresent int      `json:"ransomware_present"`
	OverdueCVEs       []string `json:"overdue_cves"`
}

func kevSummary(rows []*Finding) KEVSummary {
	s := KEVSummary{OverdueCVEs: []string{}}
	for _, f := range rows {
		if f.Status != "PRESENT" || f.HostCount <= 0 || f.KEVDaysLeft == nil {
			continue
		}
		d := *f.KEVDaysLeft
		if d < 0 {
			s.Overdue++
			s.OverdueCVEs = append(s.OverdueCVEs, f.CVE)
			if -d > s.WorstOverdueDays {
				s.WorstOverdueDays = -d
			}
		}
		if d >= 0 && d <= 14 {
			s.DueWithin14d++
		}
		if f.KEV != nil && knownRansomware(f.KEV.Ransomware) {
			s.RansomwarePresent++
		}
	}
	return s
}

// numberValue is a JSON number's value, 0 when it is empty or not a number.
func numberValue(n json.Number) float64 {
	v, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsNaN(v) {
		return 0
	}
	return v
}

func pyNumber(n json.Number) string { return pyfmt.Number(n) }

func percent(p float64) string { return pyfmt.Percent(p, 0) }
