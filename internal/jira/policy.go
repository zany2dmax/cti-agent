// Package jira files and tracks remediation tickets for confirmed exposure.
//
// This file is the policy: what a ticket says, how duplicates are recognised,
// and which project may be written to. It is pure - no network, no files, no
// environment reads - so the ticket shape and the duplicate-suppression key
// can be tested against a table rather than against crhomeusa.atlassian.net.
//
// # WHY DUPLICATE SUPPRESSION IS THE HARD PART
//
// The daily digest reports the same CVE every day until it is remediated. A
// naive "file a ticket for each Sev5" therefore files the same ticket every
// morning, and ~441 hosts across three overdue KEV entries would have produced
// a dozen tickets in the first week. The operator's instruction was explicit:
//
//	We do not want to ticket storm the IT dept.
//
// So the identity of a ticket is the CVE, not the run. One ticket per CVE,
// carrying every QID and every host for that CVE, found again on later runs by
// a label rather than by remembering - see IdempotencyLabel.
package jira

import (
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxSummary is Jira's limit on the summary field. Exceeding it is a 400 on
// create, so the summary is truncated rather than the ticket lost.
const MaxSummary = 255

// Finding is everything needed to file and describe one ticket.
//
// Deliberately not the digest's own row type: this package must not acquire a
// dependency on the report format, or changing a column in the email becomes a
// change to the ticketing contract.
type Finding struct {
	CVE      string
	QIDs     []string
	Hosts    []string
	KEV      bool
	KEVDueOn time.Time // zero when not a KEV entry
	Severity int       // 5..1, 5 highest
	CVSS     string
	Title    string
	QQL      string // the Qualys query that reproduces the host list
	FirstSeen time.Time

	// HostCount is the authoritative number of affected machines, which is
	// NOT always len(Hosts). When the scanner truncates its per-QID host
	// lists the union is short, and deriving the count from the names it
	// managed to return understates the estate. Zero means "use len(Hosts)",
	// which keeps callers that only have a list working.
	HostCount int
	// CountIsFloor means the scanner truncated, so HostCount is a lower
	// bound and the names in Hosts are incomplete.
	CountIsFloor bool
}

// Count is the number to print. Always this, never len(f.Hosts).
func (f Finding) Count() int {
	if f.HostCount > 0 {
		return f.HostCount
	}
	return len(f.Hosts)
}

// HostFloor reports whether the count is a lower bound rather than a
// measurement - either because the provider said so, or because it returned
// fewer names than it counted.
//
// This used to guess from a magic 1000. The provider knows, so ask it: saying
// "441 hosts" when the truth is "at least 441" is the kind of false precision
// this codebase has been burned by before.
func (f Finding) HostFloor() bool {
	return f.CountIsFloor || (f.HostCount > 0 && len(f.Hosts) < f.HostCount)
}

// IdempotencyLabel is how a ticket is recognised on a later run.
//
// A LABEL, not a local database. A ledger on the Fedora box would be the
// obvious choice and it is the wrong one: it goes stale the moment anybody
// closes, moves, clones or bulk-edits a ticket in the Jira UI, and then the
// fleet files a second ticket for a CVE that already has one. The label lives
// on the ticket itself, so Jira is the single source of truth about what Jira
// contains.
//
// Lowercased because Jira labels are case-sensitive and CVE ids are not
// consistently cased in the wild: CVE-2026-85880 and cve-2026-85880 must not
// become two tickets.
func IdempotencyLabel(cve string) string {
	return "cti-" + strings.ToLower(strings.TrimSpace(cve))
}

// Labels are what goes on a new ticket. The idempotency label first, then
// markers a human can filter on.
func Labels(f Finding) []string {
	out := []string{IdempotencyLabel(f.CVE), "cti-agent"}
	if f.KEV {
		out = append(out, "cisa-kev")
	}
	out = append(out, fmt.Sprintf("sev%d", f.Severity))
	return out
}

// FindJQL is the query that finds an existing ticket for this CVE.
//
// Scoped to the project and NOT scoped by status: a resolved ticket still
// counts as "already filed". Re-opening a closed ticket, or filing a fresh one
// when the vulnerability genuinely came back, is a judgement for a person -
// the fleet's job is to avoid filing a second ticket for the same thing while
// the first is still the right place to talk about it.
func FindJQL(projectKey, cve string) string {
	return fmt.Sprintf("project = %q AND labels = %q ORDER BY created ASC",
		projectKey, IdempotencyLabel(cve))
}

// Summary is the ticket title.
//
// Leads with the CVE because that is what somebody searches for, then the host
// count because that is what decides priority, and says OVERDUE outright when
// a KEV deadline has passed. A title that reads well but hides the deadline
// makes the deadline somebody else's job to notice.
func Summary(f Finding, now time.Time) string {
	var b strings.Builder
	if f.KEV && !f.KEVDueOn.IsZero() && now.After(f.KEVDueOn) {
		b.WriteString("[OVERDUE] ")
	}
	b.WriteString(f.CVE)
	b.WriteString(" - ")

	hosts := fmt.Sprintf("%d host", f.Count())
	if f.Count() != 1 {
		hosts += "s"
	}
	if f.HostFloor() {
		hosts = "at least " + hosts
	}
	b.WriteString(hosts)

	if f.KEV {
		b.WriteString(", CISA KEV")
	}
	if t := strings.TrimSpace(f.Title); t != "" {
		b.WriteString(" - " + t)
	}

	// Collapse whitespace before truncating: a newline in a summary is both a
	// rendering bug and, in a field that ends up in email notifications, a
	// header-injection primitive.
	s := strings.Join(strings.Fields(b.String()), " ")
	return truncate(s, MaxSummary)
}

// truncate cuts to n BYTES while never splitting a rune, and marks that it
// cut. Jira counts the limit in characters, so this is conservative - which is
// the correct direction for a field that 400s when exceeded.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const mark = "..."
	cut := n - len(mark)
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Description is the ticket body, in Jira wiki markup.
//
// Wiki markup, not Atlassian Document Format, because this client talks to
// REST API v2. v3 requires description as an ADF document tree, which means
// hand-assembling nested JSON for every paragraph and table - more code, more
// to get wrong, and no benefit for a ticket that is mostly a table and a list.
//
// The host list is NOT here. It goes in the CSV attachment, because 441
// hostnames inline is a description nobody reads and a page nobody can scroll,
// and because whoever does the patching wants a file they can sort and filter.
func Description(f Finding, now time.Time, csvName string) string {
	var b strings.Builder

	b.WriteString("Filed automatically by the CTI agent from confirmed scanner detections. ")
	b.WriteString("Host counts are from Qualys Host Detection, not inferred from a CVE mapping.\n\n")

	b.WriteString("||Field||Value||\n")
	b.WriteString(row("CVE", f.CVE))
	if t := strings.TrimSpace(f.Title); t != "" {
		b.WriteString(row("Title", t))
	}
	b.WriteString(row("Severity", fmt.Sprintf("Sev%d", f.Severity)))
	if f.CVSS != "" {
		b.WriteString(row("CVSS", f.CVSS))
	}

	hostCount := fmt.Sprintf("%d", f.Count())
	if f.HostFloor() {
		hostCount = "at least " + hostCount +
			" (the scanner truncated its host lists; this is a floor, and the\n"+
			" attached CSV names the ones it did return)"
	}
	b.WriteString(row("Affected hosts", hostCount))

	if len(f.QIDs) > 0 {
		b.WriteString(row("Qualys QIDs", strings.Join(sortedCopy(f.QIDs), ", ")))
	}

	if f.KEV {
		b.WriteString(row("CISA KEV", "yes"))
		if !f.KEVDueOn.IsZero() {
			due := f.KEVDueOn.Format("2006-01-02")
			if now.After(f.KEVDueOn) {
				days := int(now.Sub(f.KEVDueOn).Hours() / 24)
				due = fmt.Sprintf("%s - *OVERDUE by %d days*", due, days)
			}
			b.WriteString(row("KEV remediation due", due))
		}
	}
	if !f.FirstSeen.IsZero() {
		b.WriteString(row("First reported by CTI", f.FirstSeen.Format("2006-01-02")))
	}
	b.WriteString("\n")

	if csvName != "" {
		// _, _ = because a strings.Builder write cannot fail - Builder.Write
		// is documented to always return a nil error. Explicit at the call
		// site rather than hidden in an errcheck exclusion, which is this
		// repo's rule: the reader can see the decision was made.
		_, _ = fmt.Fprintf(&b, "The full host list is attached as [^%s].\n\n", csvName)
	}

	if q := strings.TrimSpace(f.QQL); q != "" {
		b.WriteString("h3. Reproduce in the Qualys console\n")
		b.WriteString("{code}\n" + q + "\n{code}\n\n")
	}

	b.WriteString("h3. Closing this ticket\n")
	b.WriteString("Close it when the QIDs above no longer report detections. ")
	b.WriteString("The CTI daily digest will keep listing this CVE, with this ticket's key, ")
	b.WriteString("until the scanner stops finding it - so a ticket closed while detections ")
	b.WriteString("remain will reappear in the digest rather than go quiet.\n")

	return b.String()
}

func row(k, v string) string { return "|" + k + "|" + v + "|\n" }

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// CSVName is the attachment filename. Dated, because a ticket that stays open
// across several scans accumulates attachments and "which one is current" has
// to be answerable from the filename alone.
func CSVName(cve string, now time.Time) string {
	return fmt.Sprintf("%s-hosts-%s.csv",
		strings.ToLower(strings.TrimSpace(cve)), now.Format("2006-01-02"))
}

// HostCSV renders the host list.
//
// encoding/csv rather than strings.Join, so a hostname containing a comma or a
// quote cannot shift every following column. Scanner output is not input this
// codebase controls.
func HostCSV(f Finding) ([]byte, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"hostname", "cve", "qids"}); err != nil {
		return nil, fmt.Errorf("writing CSV header: %w", err)
	}
	qids := strings.Join(sortedCopy(f.QIDs), " ")
	for _, h := range sortedCopy(f.Hosts) {
		if err := w.Write([]string{h, f.CVE, qids}); err != nil {
			return nil, fmt.Errorf("writing CSV row for %q: %w", h, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flushing CSV: %w", err)
	}
	return []byte(b.String()), nil
}

// CheckAllowed is the write gate, and it is the same decision as the mailer's
// FLEET_ALLOW_TO: this fleet may not write to a project nobody approved.
//
// Unset means create nothing. An install that reads Jira without being able to
// file into it is a legitimate state - and far better than one that guesses a
// project and files a ticket an audit trail cannot explain.
func CheckAllowed(projectKey, allowRaw string) error {
	want := strings.ToLower(strings.TrimSpace(projectKey))
	if want == "" {
		return fmt.Errorf("no project key - set JIRA_PROJECT_KEY; " +
			"the fleet will not guess where to file security findings")
	}
	for _, p := range strings.Split(allowRaw, ",") {
		if strings.EqualFold(strings.TrimSpace(p), want) {
			return nil
		}
	}
	return fmt.Errorf("project %q is not in JIRA_ALLOW_CREATE (%q); "+
		"add it to fleet.env to let the fleet file tickets there",
		projectKey, allowRaw)
}

// ShouldFile decides whether a finding earns a ticket.
//
// KEV or Sev5, per the operator's choice. Note what is NOT here: anything
// about how many tickets already exist, or how busy IT is. Volume control is
// IdempotencyLabel's job - one ticket per CVE, forever - and mixing the two
// would mean a genuine new Sev5 could be suppressed because the week was busy.
func ShouldFile(f Finding) bool { return f.KEV || f.Severity >= 5 }

// NeedsApproval reports whether a human must confirm before this is filed.
//
// KEV entries carry an external deadline, so delay is the larger risk and they
// go automatically. Everything else drafts and waits, which matches the
// fleet's standing rule: auto-send scheduled reports, gate everything else.
func NeedsApproval(f Finding) bool { return !f.KEV }
