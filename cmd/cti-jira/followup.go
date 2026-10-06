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
//
// Every failure is a warning. This runs inside run-digest, before the email
// is rendered, so a Jira or scanner problem must cost follow-up comments and
// never the digest.
func followUp(ctx context.Context, c *jira.Client, cfg config.Config,
	look hostFiller, done map[string]bool, now time.Time, forReal bool) {

	issues, err := c.Search(ctx, followUpJQL(cfg.JiraProjectKey), followUpMax)
	if err != nil {
		logf("WARNING: follow-up: searching for the fleet's tickets failed: %s - "+
			"no ticket was re-checked this run", safelog.Line(err.Error()))
		return
	}
	if len(issues) >= followUpMax {
		logf("WARNING: follow-up: %d or more fleet tickets matched; only the first "+
			"%d (oldest first) are re-checked this run", followUpMax, followUpMax)
	}

	var checked, already, nolabel, unanswered int
	for _, issue := range issues {
		cve := cveFromLabels(issue.Fields.Labels)
		switch {
		case cve == "":
			nolabel++
			logf("note   : follow-up: %s has the cti-agent label but no cti-cve-... "+
				"label, so it cannot be matched to a CVE - left alone", issue.Key)
			continue
		case done[cve]:
			already++
			continue
		}

		res, err := look(ctx, cve)
		if ok, why := followUpVerdict(res, err); !ok {
			unanswered++
			logf("note   : follow-up: %s (%s): %s - ticket left alone; a lookup "+
				"that did not answer is not a fix", issue.Key, cve, safelog.Line(why))
			continue
		}
		f := findingFromLookup(cve, res)

		if !forReal {
			logf("DRY RUN follow-up: %s (%s) would be re-checked - %d host(s) now",
				issue.Key, cve, f.Count())
			checked++
			continue
		}
		csvBody, err := jira.HostCSV(f)
		if err != nil {
			logf("WARNING: follow-up: %s: building the host CSV: %s",
				issue.Key, safelog.Line(err.Error()))
			continue
		}
		if _, rc := updateExisting(ctx, c, issue, f, csvBody, now); rc != exitOK {
			logf("WARNING: follow-up: %s was not updated", issue.Key)
			continue
		}
		checked++
	}
	logf("follow-up: %d fleet ticket(s) found, %d re-checked, %d already handled "+
		"this run, %d with no CVE label, %d left alone because the scanner could "+
		"not answer", len(issues), checked, already, nolabel, unanswered)
}
