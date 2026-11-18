package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
)

// THE FOLLOW-UP PASS
//
// Ticketing used to look only at the CVEs in that morning's mail. So a ticket
// was re-checked only on a day its CVE happened to be in the news again, and
// the one piece of good news this lane exists to deliver - "no detections
// remain, you are finished" - could never be sent at all: the morning path
// keeps PRESENT findings only, and a fully remediated CVE is by definition
// not present, so it was filtered out before anything compared it with the
// ticket.
//
// This pass starts from Jira instead of from the mail. Every fleet ticket
// that is open, or was touched in the last 30 days, is re-checked against the
// scanner and run through the SAME quiet rules as the morning path
// (updateExisting): comment on spread, on new QIDs, on reaching zero, and once
// on closed-but-still-detected. Nothing else. It never closes, reopens or
// transitions a ticket - remediation is IT's, and so is deciding it is done.

// followUpMax bounds one run. A real estate has tens of open fleet tickets;
// reaching this is either a backlog worth knowing about or a query matching
// far more than it should, and the log says which rather than quietly
// re-checking a sample.
const followUpMax = 200

// followUpWindow is how long a CLOSED ticket stays in the pass. Long enough
// to catch IT closing a ticket while the scanner still sees the CVE - the
// case worth one comment - without re-checking every ticket ever closed.
const followUpWindow = "-30d"

// followUpJQL selects the fleet's own tickets: the cti-agent marker label
// that every ticket this lane files carries, in the configured project.
func followUpJQL(projectKey string) string {
	return fmt.Sprintf(`project = %q AND labels = "cti-agent" AND `+
		`(statusCategory != Done OR updated >= %s) ORDER BY created ASC`,
		projectKey, followUpWindow)
}

// cveFromLabels recovers the CVE from a ticket's idempotency label,
// "cti-cve-2026-1234". The label rather than the summary, because the label is
// what the fleet itself matches on and a person can rewrite a summary.
func cveFromLabels(labels []string) string {
	for _, l := range labels {
		l = strings.ToLower(strings.TrimSpace(l))
		if strings.HasPrefix(l, "cti-cve-") {
			return strings.ToUpper(strings.TrimPrefix(l, "cti-"))
		}
	}
	return ""
}

// findingFromLookup is the follow-up's view of a CVE: identity, hosts, QIDs.
// The comments read nothing else, and the KEV and severity that the morning
// path carries come from the digest, which this pass does not have.
func findingFromLookup(cve string, res vulnlookup.Result) jira.Finding {
	f := jira.Finding{CVE: cve}
	applyLookup(&f, res)
	return f
}

// applyLookup copies a scanner answer onto a finding. Shared with the
// morning path, so a ticket compared from either direction is compared on
// the same numbers.
func applyLookup(f *jira.Finding, res vulnlookup.Result) {
	f.Hosts = res.Hosts
	if res.HostCount > 0 {
		f.HostCount = res.HostCount
	}
	f.CountIsFloor = res.HostCountIsFloor
	if res.MaxScore > 0 {
		// Today's QDS, not the morning report's.
		f.QDS = res.MaxScore
	}
	if len(res.ExternalIDs) > 0 {
		f.QIDs = res.ExternalIDs
		f.QQL = "vulnerabilities.vulnerability.qid:[" + strings.Join(f.QIDs, ",") + "]"
	}
}

// followUpVerdict decides whether a scanner answer may be compared with a
// ticket at all.
//
// ONLY PRESENT AND NOT_PRESENT. This is the line that keeps the pass from
// telling IT a vulnerability is fixed because a lookup failed. UNKNOWN - no
// QID mapping yet, or a Qualys outage, which the provider reports as UNKNOWN
// with an error - says nothing about the estate, and reading its zero host
// count as "remediated" would post a false all-clear on a live exposure.
func followUpVerdict(res vulnlookup.Result, err error) (ok bool, why string) {
	switch {
	case err != nil:
		return false, "the scanner lookup failed: " + err.Error()
	case strings.EqualFold(res.Status, vulnlookup.StatusPresent),
		strings.EqualFold(res.Status, vulnlookup.StatusNotPresent):
		return true, ""
	}
	why = "the scanner could not say (status " + res.Status
	if res.Reason != "" {
		why += ": " + res.Reason
	}
	return false, why + ")"
}

// followUp re-checks the fleet's tickets. done holds the CVEs the morning
// path already handled this run, so no ticket is compared twice in one run.
// A nil look lists every ticket and checks none (the digest's ticket list
// when the scanner will not load); it must come with forReal false.
//
// Every failure is a warning. This runs inside run-digest, before the email
// is rendered, so a Jira or scanner problem must cost follow-up comments and
// never the digest.
//
// It returns a reference for EVERY fleet ticket it found, checked or not, so
// the digest can link a finding to its ticket on any day. The map used to hold
// only the tickets the morning path filed or updated from that day's findings,
// so a ticketed CVE showed its link only on a day it was back in the mail -
// and the weekly, which skips ticketing, showed almost none.
func followUp(ctx context.Context, c *jira.Client, cfg config.Config,
	look hostFiller, done map[string]bool, now time.Time, forReal bool) map[string]TicketRef {

	refs := map[string]TicketRef{}
	issues, err := c.Search(ctx, followUpJQL(cfg.JiraProjectKey), followUpMax)
	if err != nil {
		logf("WARNING: follow-up: searching for the fleet's tickets failed: %s - "+
			"no ticket was re-checked this run", safelog.Line(err.Error()))
		return refs
	}
	// The domains lock-down ticket and the VM scan lane's spreadsheet ticket
	// may live in other projects (INF, say). Each is listed for the digest like
	// any fleet ticket, and only that: the loop below leaves them alone, and
	// their own weekly runs keep them current.
	searched := map[string]bool{strings.ToUpper(cfg.JiraProjectKey): true}
	for _, extra := range []struct{ project, label, what string }{
		{cfg.DomainsProject(), domainsLabel, "the domains lock-down ticket"},
		{cfg.VMScanProject(), vmscanFixesLabel, "the spreadsheet ticket"},
		{cfg.JiraSupplierProject, supplierLabel, "the supplier-request items"},
	} {
		if strings.TrimSpace(extra.project) == "" || searched[strings.ToUpper(extra.project)] {
			continue
		}
		searched[strings.ToUpper(extra.project)] = true
		more, err := c.Search(ctx, followUpJQL(extra.project), followUpMax)
		if err != nil {
			logf("WARNING: follow-up: searching %s for %s failed: %s - it is not listed in the digest this run",
				extra.project, extra.what, safelog.Line(err.Error()))
		}
		for _, is := range more {
			if hasLabel(is.Fields.Labels, domainsLabel) || hasLabel(is.Fields.Labels, vmscanFixesLabel) ||
				hasLabel(is.Fields.Labels, supplierLabel) {
				issues = append(issues, is)
			}
		}
	}
	if len(issues) >= followUpMax {
		logf("WARNING: follow-up: %d or more fleet tickets matched; only the first "+
			"%d (oldest first) are re-checked this run", followUpMax, followUpMax)
	}

	// The write gate covers updates too. Closed, the pass still runs - it
	// still returns every ticket's link for the digest - but only as the
	// read-only preview, the same as a dry run.
	if forReal {
		if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
			logf("WRITE GATE CLOSED - follow-up runs read-only, no ticket will be "+
				"commented on: %s", safelog.Line(err.Error()))
			forReal = false
		}
	}

	var checked, already, other, unanswered, lockdown, sheet, supplier int
	for _, issue := range issues {
		// The domains lane's lock-down ticket carries the cti-agent label
		// too. It is not about a CVE and is kept current by run-domains
		// (--domains-actions), so it is listed for the digest and left alone
		// here - it used to be counted as "no CVE label" with a note saying
		// it could not be matched, which read like a fault.
		if hasLabel(issue.Fields.Labels, domainsLabel) {
			lockdown++
			r := refFor(c, issue, "")
			r.Outcome = "the weekly domains lock-down ticket - updated by the weekly domains run"
			r.Kind = "domains-lockdown"
			refs[lockdownRefKey] = r
			continue
		}
		// The VM scan lane's spreadsheet ticket, the same way: not about a CVE,
		// kept current by run-vmscan (--vmscan-fixes), listed here only.
		if hasLabel(issue.Fields.Labels, vmscanFixesLabel) {
			sheet++
			r := refFor(c, issue, "")
			r.Outcome = "the network team's spreadsheet ticket - updated by the weekly VM scan run"
			r.Kind = "vmscan-sheet-fixes"
			refs[sheetFixesRefKey] = r
			continue
		}
		// A supplier-request Kanban item: the supplier lane files and updates
		// it; one row each, listed here only.
		if hasLabel(issue.Fields.Labels, supplierLabel) {
			supplier++
			r := refFor(c, issue, "Supplier request")
			r.Outcome = "a supplier-request item - kept current by the supplier lane"
			r.Kind = "supplier-request"
			refs["supplier:"+issue.Key] = r
			continue
		}
		cve := cveFromLabels(issue.Fields.Labels)
		if cve != "" && cve != testCVE {
			// Oldest first, so if two tickets carry one CVE the newer wins.
			refs[cve] = refFor(c, issue, cve)
		}
		switch {
		case cve == "":
			// A fleet ticket of a kind this pass does not know: still the
			// fleet's, so it is listed for the digest (every ticket the fleet
			// files is shown there), not re-checked.
			other++
			r := refFor(c, issue, "Fleet ticket")
			r.Outcome = "a fleet ticket this daily re-check does not cover - listed so it is not lost"
			r.Kind = "fleet-other"
			refs["fleet:"+issue.Key] = r
			continue
		case done[cve]:
			already++
			continue
		case cve == testCVE:
			// The setup test ticket. It carried the cti-agent label before
			// test tickets were given their own. Only worth a word if it is
			// still open: a closed one is in the pass because of the 30-day
			// window for closed tickets, and drops out by itself.
			if !issue.IsDone() {
				logf("note   : follow-up: %s is the setup test ticket (%s) - close it in Jira",
					issue.Key, testCVE)
			}
			continue
		}

		if look == nil {
			// No scanner this run: listed for the digest, not compared and
			// never commented on.
			if r, ok := refs[cve]; ok && r.Key == issue.Key {
				r.Outcome = "listed only - not re-checked this run (the scanner was unavailable)"
				refs[cve] = r
			}
			continue
		}
		res, err := look(ctx, cve)
		if ok, why := followUpVerdict(res, err); !ok {
			unanswered++
			logf("note   : follow-up: %s (%s): %s - ticket left alone; a lookup "+
				"that did not answer is not a fix", issue.Key, cve, safelog.Line(why))
			if r, ok := refs[cve]; ok && r.Key == issue.Key {
				r.Outcome = "not re-checked: " + safelog.Line(why)
				refs[cve] = r
			}
			continue
		}
		f := findingFromLookup(cve, res)
		// Record what the scanner said and what this run did, on the ref the
		// digest will render. With two tickets for one CVE the newer one's
		// iteration runs later and overwrites, so it owns the line.
		note := func(outcome string) {
			if r, ok := refs[cve]; ok && r.Key == issue.Key {
				r.Checked, r.Hosts, r.Outcome = true, f.Count(), outcome
				refs[cve] = r
			}
		}

		if !forReal {
			// The same decision the real run acts on, read-only: whether IT
			// gets a comment, and why - not just a host count to interpret.
			preview := previewUpdate(ctx, c, issue, f, now)
			logf("DRY RUN follow-up: %s (%s): %s", issue.Key, cve, preview)
			note(preview)
			checked++
			continue
		}
		csvBody, err := jira.HostCSV(f)
		if err != nil {
			logf("WARNING: follow-up: %s: building the host CSV: %s",
				issue.Key, safelog.Line(err.Error()))
			continue
		}
		_, outcome, rc := updateExisting(ctx, c, issue, f, csvBody, now)
		if rc != exitOK {
			logf("WARNING: follow-up: %s was not updated", issue.Key)
			note("re-checked, but the Jira update failed - see the run log")
			continue
		}
		note(outcome)
		checked++
	}
	logf("follow-up: %d fleet ticket(s) found, %d re-checked, %d already handled "+
		"this run, %d domains lock-down, %d spreadsheet, %d supplier, %d other fleet ticket(s) listed, "+
		"%d left alone because the scanner could not answer",
		len(issues), checked, already, lockdown, sheet, supplier, other, unanswered)
	return refs
}

// lockdownRefKey is the domains lock-down ticket's key in the ticket map,
// which is otherwise keyed by CVE. The digest shows it under FLEET TICKETS.
const lockdownRefKey = "DNS lock-down"

// sheetFixesRefKey is the spreadsheet ticket's key in the same map.
const sheetFixesRefKey = "Spreadsheet fixes"

// supplierLabel marks the supplier lane's Kanban items (internal/supplier).
const supplierLabel = "fleet-supplier"

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if strings.EqualFold(strings.TrimSpace(l), want) {
			return true
		}
	}
	return false
}
