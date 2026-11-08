// Package vmscan reads Qualys VMDR (vulnerability management) scan-result
// notifications and combines the week's scheduled scans into one notice that
// they ran and what they covered.
//
// The report carries no vulnerability counts or severities, on purpose: its
// audience does not act on them from this email, and the two scheduled scans
// overlap, so adding them up would mislead. The parser still reads the
// counts (they are in the notice, and a later use may want them); the report
// does not show them.
//
// The notice is Qualys's "Qualys: Scan Results" email, generated from a fixed
// template, so this keys on its label text ("Scan Title :", "Target Groups :")
// and not on its HTML. The web-application scanner has its own, different
// notices (internal/appscan/qualys); the two do not share a parser because
// their subjects, fields and meaning differ.
//
// # WHAT A NOTICE CARRIES
//
// The scan's title, when it started and how long it ran, the Target Groups
// (Asset Group titles) it covered, how many hosts it scanned and how many were
// alive, and the confirmed and potential vulnerability counts by severity with
// their trend (new, reopened, active, closed since the last scan).
//
// # THINGS THAT HAVE BEEN WRONG IN REAL MAIL
//
//   - An invisible byte-order mark sits in front of one group name in the
//     Target Groups line. Left in, that name never matches anything.
//   - The message repeats its first lines in a hidden preheader, and wraps the
//     real text in a <pre>. Only the <pre> is read.
//   - Two notices can arrive for one run if the schedule notifies twice.
//     Results are deduplicated on the scan's report reference.
package vmscan

import (
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan/qualys"
)

// Counts is one severity row: the total and its trend.
type Counts struct {
	Total    int
	New      int
	Reopened int
	Active   int
	Closed   int
}

// Severities holds severity 1 (Minimal) through 5 (Urgent) at indexes 1-5.
type Severities [6]Counts

// Sum is the total across severities.
func (s Severities) Sum() int {
	n := 0
	for i := 1; i <= 5; i++ {
		n += s[i].Total
	}
	return n
}

// Scan is one scan run as reported by its notice.
type Scan struct {
	Title        string
	Start        time.Time
	Duration     time.Duration
	TargetGroups []string
	HostsScanned int
	ActiveHosts  int
	Profile      string
	LaunchedBy   string
	LaunchType   string
	Status       string

	// Confirmed and Potential are the two vulnerability tables. They are kept
	// apart: a potential finding is "might be there", and adding it to the
	// confirmed count overstates exposure.
	Confirmed Severities
	Potential Severities
	// InfoTotal is the information-gathered total, shown for completeness.
	InfoTotal int

	// ReportURL is Qualys's report page for the run, verified as a Qualys
	// host. Rendered as plain text, never a link.
	ReportURL string
	// Ref is the scan reference in that URL ("scan/1793275220.51060"), the
	// key that identifies one run.
	Ref string

	// MessageID and Received identify the message, for the mailbox cleanup.
	MessageID string
	Received  time.Time
}

// Finished reports whether the scan ran to completion.
func (s Scan) Finished() bool { return strings.EqualFold(strings.TrimSpace(s.Status), "finished") }

// Provider parses Qualys VM scan-result notices.
type Provider struct{}

// Name is the lane's key.
func (Provider) Name() string { return "qualys-vm" }

const resultsSubject = "qualys: scan results"

// qualysDomains are the sender domains a notice may come from, exactly. A
// substring test on "Name <addr>" would pass a display name of
// "qualys@qualys.net" or an address at qualys.net.attacker.example.
var qualysDomains = map[string]bool{"qualys.net": true, "qualys.com": true}

func senderDomain(from string) string {
	a := strings.TrimSpace(from)
	if i := strings.LastIndex(a, "<"); i >= 0 {
		a = strings.TrimSuffix(a[i+1:], ">")
	}
	if i := strings.LastIndex(a, "@"); i >= 0 {
		return strings.ToLower(strings.TrimSpace(a[i+1:]))
	}
	return ""
}

// Recognises is true for a Qualys results notice, from the sender and subject
// alone. The subject is a prefix, so a person's "FW:" or "RE:" is not one.
func (Provider) Recognises(sender, subject string) bool {
	return qualysDomains[senderDomain(sender)] &&
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(subject)), resultsSubject)
}

// Lookalike is true for a message with the notice's subject from an address
// that is not Qualys's: a scan whose notification sender was set to the team
// mailbox itself. Such a message is never read as a result, and is never
// silently dropped either.
func (Provider) Lookalike(sender, subject string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(subject)), resultsSubject) &&
		!qualysDomains[senderDomain(sender)]
}

var (
	preRE    = regexp.MustCompile(`(?is)<pre[^>]*>(.*?)</pre>`)
	tagRE    = regexp.MustCompile(`(?s)<[^>]*>`)
	hrefRE   = regexp.MustCompile(`(?i)href="([^"]*report_view\.php[^"]*)"`)
	fieldRE  = regexp.MustCompile(`^([A-Za-z][A-Za-z ()+-]*?)\s*:\s*(.*)$`)
	sevRE    = regexp.MustCompile(`^Severity\s+([1-5])\s+"[^"]*"\s*:\s*(\d+)(?:\s*\(\s*(-?\d+)\s*,\s*(-?\d+)\s*,\s*(-?\d+)\s*,\s*(-?\d+)\s*\))?`)
	totalRE  = regexp.MustCompile(`^Total\s*:\s*(\d+)`)
	startRE  = regexp.MustCompile(`^(\d{2}/\d{2}/\d{4}) at (\d{2}:\d{2}:\d{2} [AP]M)(?:\s*\(GMT([+-]\d{4})\))?`)
	durRE    = regexp.MustCompile(`^(?:(\d+) days?\s+)?(\d+):(\d{2}):(\d{2})$`)
	refRE    = regexp.MustCompile(`ref=scan[/*]([0-9.]+)`)
	spaceRE  = regexp.MustCompile(`\s+`)
	invisRep = strings.NewReplacer("\ufeff", "", "\u200b", "", "\u00a0", " ")
)

// text is the notice's readable text: the <pre>, tags removed, entities
// decoded, invisible characters dropped.
func text(body string) []string {
	s := body
	if m := preRE.FindStringSubmatch(body); m != nil {
		s = m[1]
	}
	s = tagRE.ReplaceAllString(s, " ")
	s = invisRep.Replace(html.UnescapeString(s))
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(strings.ReplaceAll(l, "\t", " ")); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Parse reads one notice body (HTML preferred). Problems are not errors: a
// notice that parsed most of the way is still worth reporting, and a template
// change should announce itself rather than show up as a thinner report.
func (Provider) Parse(body string) (Scan, []string) {
	var s Scan
	var problems []string
	lines := text(body)

	if m := hrefRE.FindStringSubmatch(body); m != nil {
		raw := html.UnescapeString(m[1])
		if u, err := qualys.UnwrapReportLink(raw); err == nil {
			s.ReportURL = u
			if r := refRE.FindStringSubmatch(u); r != nil {
				s.Ref = "scan/" + r[1]
			}
		} else {
			problems = append(problems, "the scan report link did not resolve to a Qualys host: "+err.Error())
		}
	}

	section := ""
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "Summary of discovered Vulnerabilities"):
			section = "confirmed"
			continue
		case strings.HasPrefix(l, "Summary of Potential Vulnerabilities"):
			section = "potential"
			continue
		case strings.HasPrefix(l, "Summary of Information Gathered"):
			section = "info"
			continue
		}
		if m := sevRE.FindStringSubmatch(l); m != nil && (section == "confirmed" || section == "potential") {
			sev, _ := strconv.Atoi(m[1])
			c := Counts{Total: atoi(m[2])}
			if m[3] != "" {
				c.New, c.Reopened, c.Active, c.Closed = atoi(m[3]), atoi(m[4]), atoi(m[5]), atoi(m[6])
			}
			if section == "confirmed" {
				s.Confirmed[sev] = c
			} else {
				s.Potential[sev] = c
			}
			continue
		}
		if m := totalRE.FindStringSubmatch(l); m != nil && section == "info" {
			s.InfoTotal = atoi(m[1])
			continue
		}
		m := fieldRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[2])
		switch strings.ToLower(strings.TrimSpace(m[1])) {
		case "scan title":
			s.Title = v
		case "start date":
			s.Start = parseStart(v)
		case "duration":
			s.Duration = parseDuration(v)
		case "target groups":
			s.TargetGroups = splitGroups(v)
		case "hosts scanned":
			s.HostsScanned = atoi(v)
		case "active hosts":
			s.ActiveHosts = atoi(v)
		case "option profile":
			s.Profile = v
		case "launched by":
			s.LaunchedBy = v
		case "launch type":
			s.LaunchType = v
		case "scan status":
			s.Status = v
		}
	}

	if s.Title == "" {
		problems = append(problems, "no scan title found in the notice")
	}
	if s.Start.IsZero() {
		problems = append(problems, "no readable start date in the notice")
	}
	if len(s.TargetGroups) == 0 {
		problems = append(problems, "no target groups listed in the notice")
	}
	if s.Status == "" {
		problems = append(problems, "no scan status in the notice")
	}
	if s.Ref == "" {
		problems = append(problems, "no scan reference found, so a duplicate notice cannot be recognised")
	}
	return s, problems
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// parseStart reads "10/29/2026 at 12:00:19 PM (GMT+0000)".
func parseStart(v string) time.Time {
	m := startRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return time.Time{}
	}
	loc := time.UTC
	if m[3] != "" {
		sign := 1
		if m[3][0] == '-' {
			sign = -1
		}
		h, mi := atoi(m[3][1:3]), atoi(m[3][3:5])
		loc = time.FixedZone("GMT"+m[3], sign*(h*3600+mi*60))
	}
	t, err := time.ParseInLocation("01/02/2006 03:04:05 PM", m[1]+" "+m[2], loc)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseDuration reads "22:07:17" and "1 day 00:02:33".
func parseDuration(v string) time.Duration {
	m := durRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0
	}
	d := time.Duration(atoi(m[1]))*24*time.Hour + time.Duration(atoi(m[2]))*time.Hour +
		time.Duration(atoi(m[3]))*time.Minute + time.Duration(atoi(m[4]))*time.Second
	return d
}

// splitGroups splits the Target Groups line on commas and trims each name.
// Group names may contain parentheses and spaces but not commas.
func splitGroups(v string) []string {
	var out []string
	for _, g := range strings.Split(v, ",") {
		if g = strings.TrimSpace(spaceRE.ReplaceAllString(g, " ")); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// # COMPANION NOTICES
//
// For every scan Qualys also sends "Qualys: Scan Completed" (the summary
// without the vulnerability tables) and "Qualys: Completed Vulnerability Scan
// Notification" (the task-owner notice). Neither carries anything the report
// uses, so once the lane has reported on the run they are claimed for the
// mailbox cleanup to DELETE, not archive - the operator's call. They are
// matched to the run, never claimed on subject alone: "Scan Completed" carries
// the same report reference as the results notice; the task-owner notice only
// a title and launch time, which must both equal the run's.

const (
	completedSubject = "qualys: scan completed"
	taskDoneSubject  = "qualys: completed vulnerability scan notification"
)

// Companion identifies the run a companion notice is about.
type Companion struct {
	Title string
	Start time.Time
	Ref   string
}

// RecognisesCompanion is true for a companion notice from Qualys itself. A
// prefix match on the subject, as for results, so a person's forward is not
// one; and the sender's domain exactly, so a lookalike is never claimed.
func (Provider) RecognisesCompanion(sender, subject string) bool {
	if !qualysDomains[senderDomain(sender)] {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(subject))
	return strings.HasPrefix(s, completedSubject) || strings.HasPrefix(s, taskDoneSubject)
}

// ParseCompanion reads the run's identity out of a companion notice:
// "Scan Title"/"Start Date" in Scan Completed, "Title"/"Launch Time" in the
// task-owner notice, and the report reference where there is one.
func (Provider) ParseCompanion(body string) Companion {
	var c Companion
	if r := refRE.FindStringSubmatch(body); r != nil {
		c.Ref = "scan/" + r[1]
	}
	for _, l := range text(body) {
		m := fieldRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[2])
		switch strings.ToLower(strings.TrimSpace(m[1])) {
		case "scan title", "title":
			if c.Title == "" {
				c.Title = v
			}
		case "start date", "launch time":
			if c.Start.IsZero() {
				c.Start = parseStart(v)
			}
		}
	}
	return c
}

// Matches reports whether the companion is about this run. The report
// reference decides when both have one; otherwise the title and the start
// time must both be present and equal. Nothing partial matches.
func (c Companion) Matches(s Scan) bool {
	if c.Ref != "" && s.Ref != "" {
		return c.Ref == s.Ref
	}
	if c.Title == "" || c.Start.IsZero() || s.Start.IsZero() {
		return false
	}
	return strings.EqualFold(spaceRE.ReplaceAllString(strings.TrimSpace(c.Title), " "),
		spaceRE.ReplaceAllString(strings.TrimSpace(s.Title), " ")) && c.Start.Equal(s.Start)
}

// FormatDuration renders a duration the way the report shows it: "22h07m" or
// "1d 00h02m".
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "unknown"
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	if days > 0 {
		return fmt.Sprintf("%dd %02dh%02dm", days, h, m)
	}
	return fmt.Sprintf("%dh%02dm", h, m)
}
