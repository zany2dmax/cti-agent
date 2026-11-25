package appscan

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// UNSCANNED APPLICATIONS AND THE AUDIT
//
// The weekly report and the owners lane both start from the scans that ran.
// An application with no scan is in neither, so a schedule switched off in
// the scanner, or never set up, was invisible: the reports looked complete
// while a third of the applications went untested. NotScannedApps lists those,
// for the weekly report; Audit joins every application the scanner defines
// to its owner, its newest scan and its newest owner report, for the
// operator (cti-appscan --audit).

// BareFinished reports whether a status is the newer notice format's plain
// "Finished", which needs the scanner's scan list to confirm the run: when no
// matching run is found (or the list cannot be read) the scan is not counted
// as complete. The same test as qualys.BareFinished.
func BareFinished(status string) bool {
	return strings.EqualFold(strings.Join(strings.Fields(status), ""), "finished")
}

// scanOf is the scan in week that belongs to app: by the scanner's id, else
// the notification's id, else by name.
func scanOf(app App, week []ScanResult) (ScanResult, bool) {
	id := strings.TrimSpace(app.ID)
	if id != "" {
		for _, s := range week {
			if strings.TrimSpace(s.AppID) == id || strings.TrimSpace(s.NoticeAppID) == id {
				return s, true
			}
		}
	}
	name := nameKey(app.Name)
	for _, s := range week {
		if s.AppKey() == "" && name != "" && nameKey(s.App) == name {
			return s, true
		}
	}
	return ScanResult{}, false
}

// NotScannedApps is every application the scanner defines with no scan in week,
// by name.
func NotScannedApps(apps []App, week []ScanResult) []App {
	var out []App
	for _, a := range apps {
		if _, ok := scanOf(a, week); !ok {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// AuditRow is one application's line in the audit.
type AuditRow struct {
	App     App
	Owner   string // the owner's email, or empty
	Scan    *ScanResult
	Report  *DeliveredEntry // the owners lane's newest entry for it
	Verdict string
	// Problem is true when somebody should act: not scanned, no owner, a
	// scan that did not finish, a held or missing report.
	Problem bool
}

// Audit is every application the scanner defines, joined to its owner, its
// newest scan in week (the window the caller read) and the owners lane's
// newest entry for it.
func Audit(apps []App, week []ScanResult, owners Owners, delivered DeliveredLog) []AuditRow {
	var rows []AuditRow
	for _, a := range apps {
		r := AuditRow{App: a}
		if w, ok := owners.For(a.ID, a.Name); ok {
			r.Owner = w.Email
		}
		if s, ok := scanOf(a, week); ok {
			r.Scan = &s
			if e, ok := delivered[AppKey(s)]; ok {
				r.Report = &e
			}
		} else if e, ok := delivered[strings.TrimSpace(a.ID)]; ok {
			r.Report = &e
		}
		r.Verdict, r.Problem = verdict(r)
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Problem != rows[j].Problem {
			return rows[i].Problem // problems first
		}
		return strings.ToLower(rows[i].App.Name) < strings.ToLower(rows[j].App.Name)
	})
	return rows
}

func verdict(r AuditRow) (string, bool) {
	if r.Scan == nil {
		why := "not scanned in this window - check its schedule in the scanner"
		if r.Report != nil && r.Report.Status == "sent" {
			why += fmt.Sprintf(" (last report sent %s)", r.Report.At.UTC().Format("2006-01-02"))
		}
		return why, true
	}
	s := *r.Scan
	matched := r.Report != nil && r.Report.Ref == ScanRef(s)
	switch {
	case r.Owner == "":
		return "scanned, but no owner on file - its reports are held", true
	case !s.Complete && BareFinished(s.Status):
		return "the scanner says it finished, but the run is not in its scan list - not confirmed, no report", true
	case !s.Complete:
		return "scan did not finish (" + orUnknown(s.Status) + ") - no report", true
	case s.Auth.Failed():
		return "the scan's login failed (" + orUnknown(s.Auth.Status) + ")", true
	case s.Unreachable():
		return "no host answered the scan - nothing was tested", true
	case matched && r.Report.Status == "sent":
		return "report sent " + r.Report.At.UTC().Format("2006-01-02"), false
	case matched:
		return r.Report.Status, true
	default:
		return "scanned, report not sent yet", true
	}
}

// RenderAudit is the audit as plain text: a table, then a count of each kind
// of problem.
func RenderAudit(rows []AuditRow, window time.Duration) string {
	var b strings.Builder
	problems := 0
	for _, r := range rows {
		if r.Problem {
			problems++
		}
	}
	fmt.Fprintf(&b, "%d web application(s) in the scanner; scans in the last %s; %d need a look\n\n",
		len(rows), windowText(window), problems)
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "APP ID\tAPPLICATION\tOWNER\tLAST SCAN\tVERDICT")
	for _, r := range rows {
		scan := "-"
		if r.Scan != nil {
			t := r.Scan.Finished
			if t.IsZero() {
				t = r.Scan.Started
			}
			scan = "?"
			if !t.IsZero() {
				scan = t.UTC().Format("2006-01-02")
			}
		}
		owner := r.Owner
		if owner == "" {
			owner = "-"
		}
		mark := "  "
		if r.Problem {
			mark = "! "
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s%s\n", oneLineName(r.App.ID), oneLineName(r.App.Name),
			oneLineName(owner), scan, mark, oneLineName(r.Verdict))
	}
	_ = w.Flush()
	return b.String()
}

// windowText is a duration as days when it is whole days ("7 days").
func windowText(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	}
	return d.String()
}
