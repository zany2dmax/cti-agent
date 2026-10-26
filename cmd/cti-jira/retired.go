package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// RETIRED APPLICATIONS
//
// An application's ticket is about a web app the scanner defines. When the
// web app is deleted from the scanner there is nothing left to scan and nobody
// to fix anything, so the ticket is closed by the lane that opened it, with a
// comment saying why. This is the only place the fleet changes a ticket's
// status, and it is deliberately narrow:
//
//   - only when cti-appscan fetched the scanner's COMPLETE web app list this
//     run (TicketsFile.ScannerApps) - a failed or skipped fetch closes nothing;
//   - only tickets carrying the fleet's own cti-appscan labels, whose app is
//     named by a numeric scanner id (name-keyed apps cannot be told apart from
//     a rename, so they are left alone);
//   - never more than maxRetirePerRun in one run. A scanner account that lost
//     visibility of its web apps looks exactly like every application being
//     retired at once; a few closures are housekeeping, many are a fault, and
//     a fault must not close the queue;
//   - only when the project is in JIRA_ALLOW_CLOSE (its own allowlist) and the
//     run is --for-real.
//
// Closing is reversible by a person (reopen the ticket), and the next run
// files a fresh ticket linked to this one if the application comes back with
// findings.

const (
	// maxRetirePerRun is the most tickets one run will close.
	maxRetirePerRun = 3
	// retireSearchMax is the page read when looking for open AppSec tickets. A
	// full page means there may be more, and the check is skipped rather than
	// judged on a sample.
	retireSearchMax = 100
)

// openAppscanJQL is every open AppSec ticket of the fleet.
func openAppscanJQL(projectKey string) string {
	return fmt.Sprintf(`project = %q AND labels = %q AND statusCategory != Done ORDER BY created ASC`,
		projectKey, appscanLabel)
}

// appIDFromLabels returns the scanner id in an app label ("cti-appscan-<id>"),
// when the ticket is for an id-keyed application. The shared "cti-appscan"
// label and name-keyed labels (a slug and hash) are not ids.
func appIDFromLabels(labels []string) (string, bool) {
	const prefix = appscanLabel + "-"
	for _, l := range labels {
		rest, ok := strings.CutPrefix(l, prefix)
		if !ok || rest == "" {
			continue
		}
		digits := true
		for _, r := range rest {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		if digits {
			return rest, true
		}
	}
	return "", false
}

// retireCandidate is an open ticket whose application is no longer in the
// scanner.
type retireCandidate struct {
	Issue jira.Issue
	AppID string
}

// planRetire decides, without touching Jira, which open tickets belong to
// applications the scanner no longer defines. Pure, so it is tested. A
// non-empty why means "nothing is closed, and here is why" (or, with no
// candidates, nothing to say).
//
// scanned are the ids of the applications this run's scans and tickets name:
// each must be in the scanner's list, or the list is inconsistent with the run
// that produced it and nothing is judged. fleetFiled, when set, says whether
// a ticket was written by the fleet (it carries the fleet's state property),
// because labels alone can be added by anyone who may edit the ticket.
func planRetire(open []jira.Issue, scannerApps, scanned []string,
	fleetFiled func(jira.Issue) bool) (retire []retireCandidate, why string) {

	if len(scannerApps) == 0 {
		return nil, "the scanner's web app list was not fetched this run, so no ticket is judged retired"
	}
	if len(open) >= retireSearchMax {
		return nil, fmt.Sprintf("%d or more open AppSec tickets: too many to judge from one page, so none is judged retired", retireSearchMax)
	}
	known := map[string]bool{}
	for _, id := range scannerApps {
		known[strings.TrimSpace(id)] = true
	}
	for _, id := range scanned {
		if id = strings.TrimSpace(id); id != "" && !known[id] {
			return nil, fmt.Sprintf("application id %s was scanned this week but is missing from the scanner's "+
				"web app list, so the list cannot be trusted - none was closed", id)
		}
	}
	idKeyed := 0
	for _, is := range open {
		if !hasLabel(is.Fields.Labels, appscanLabel) {
			continue
		}
		id, ok := appIDFromLabels(is.Fields.Labels)
		if !ok {
			continue
		}
		idKeyed++
		if known[id] {
			continue
		}
		if fleetFiled != nil && !fleetFiled(is) {
			logf("retired: %s carries the AppSec labels but not the fleet's state, so it was not "+
				"filed by the fleet - left alone", safelog.Line(is.Key))
			continue
		}
		retire = append(retire, retireCandidate{Issue: is, AppID: id})
	}
	if len(retire) > maxRetirePerRun {
		return nil, fmt.Sprintf("%d tickets belong to applications missing from the scanner's list; "+
			"more than %d at once looks like a fault (lost scanner visibility?), not retirements - "+
			"none was closed", len(retire), maxRetirePerRun)
	}
	// Most of the queue vanishing at once is the same fault on a small queue.
	if len(retire) > 1 && len(retire)*2 > idKeyed {
		return nil, fmt.Sprintf("%d of the %d open AppSec tickets belong to applications missing from the "+
			"scanner's list; that many at once looks like a fault, not retirements - none was closed",
			len(retire), idKeyed)
	}
	return retire, ""
}

// maxTicketsAge is how old a --tickets-out file may be and still be trusted to
// say which applications exist: it is written and used in the same run, so a
// day-old file is a hand-run on stale input.
const maxTicketsAge = 24 * time.Hour

// retireComment is what the closed ticket says.
func retireComment(is jira.Issue, appID string, now time.Time) string {
	return fmt.Sprintf("The weekly application-security check on %s no longer finds web application id %s "+
		"(%s) in the scanner, so there is nothing left to scan and this ticket was closed automatically "+
		"by the AppSec lane. If the same web application is scanned again and has findings of Serious "+
		"severity or above, a new ticket is filed and linked to this one.",
		now.Format("2 January 2006"), appID, wikiEscape(oneLine(is.Fields.Summary, 120)))
}

// closeOutcome says what happened to one ticket.
type closeOutcome string

const (
	closed      closeOutcome = "closed"
	wouldClose  closeOutcome = "would-close"
	closeGated  closeOutcome = "gate-closed"
	closeFailed closeOutcome = "error"
)

// closeTicket closes one ticket with comment, or says what it would do.
// Everything that can refuse - the allowlist, the transition choice - is
// settled before anything is written.
func closeTicket(ctx context.Context, c *jira.Client, cfg config.Config, is jira.Issue,
	comment string, forReal bool) closeOutcome {

	gateErr := jira.CheckCloseAllowed(cfg.JiraProjectKey, cfg.JiraAllowClose)
	ts, err := c.Transitions(ctx, is.Key)
	if err != nil {
		logf("close: %s: could not read its workflow transitions: %s", is.Key, safelog.Line(err.Error()))
		return closeFailed
	}
	choice, err := jira.ChooseClose(ts, cfg.JiraCloseTransition)
	if err != nil {
		logf("close: %s: left open - %s", is.Key, safelog.Line(err.Error()))
		return closeFailed
	}
	if !forReal {
		gate := ""
		if gateErr != nil {
			gate = " (the close gate is shut: JIRA_ALLOW_CLOSE)"
		}
		fmt.Printf("===== would close %s via transition %q to %q%s\n%s\n",
			safelog.Line(is.Key), safelog.Line(oneLine(choice.Transition.Name, 60)),
			safelog.Line(oneLine(choice.Transition.To.Name, 60)), gate, safelog.Line(comment))
		return wouldClose
	}
	if gateErr != nil {
		logf("close: %s: CLOSE GATE SHUT - %s", is.Key, safelog.Line(gateErr.Error()))
		return closeGated
	}
	if err := c.Close(ctx, is.Key, choice, comment); err != nil {
		logf("close: %s: the transition was refused: %s", is.Key, safelog.Line(err.Error()))
		return closeFailed
	}
	logf("close: %s closed (%s)", is.Key, safelog.Line(choice.Transition.To.Name))
	return closed
}

// retireOrphans closes the open AppSec tickets of applications the scanner no
// longer defines. Best effort and last in the run: nothing here can stop a
// ticket from being filed or updated.
func retireOrphans(ctx context.Context, c *jira.Client, cfg config.Config,
	tf appscan.TicketsFile, forReal bool, now time.Time) {

	if len(tf.ScannerApps) == 0 {
		logf("retired: skipped - the scanner's web app list was not fetched this run")
		return
	}
	if tf.Generated.IsZero() || now.Sub(tf.Generated) > maxTicketsAge || tf.Generated.After(now.Add(time.Hour)) {
		logf("retired: skipped - the tickets file is not from this run (generated %s), so its list of "+
			"applications may be stale", tf.Generated.Format(time.RFC3339))
		return
	}
	open, err := c.Search(ctx, openAppscanJQL(cfg.JiraProjectKey), retireSearchMax)
	if err != nil {
		logf("retired: could not list the open AppSec tickets: %s", safelog.Line(err.Error()))
		return
	}
	var scanned []string
	for _, t := range tf.Tickets {
		scanned = append(scanned, t.AppID)
	}
	// A ticket the fleet filed carries its state property; a label alone proves
	// nothing, since anyone who may edit a ticket can add one.
	fleetFiled := func(is jira.Issue) bool {
		var st appscanState
		found, err := c.GetProperty(ctx, is.Key, appscanPropKey, &st)
		return err == nil && found
	}
	retire, why := planRetire(open, tf.ScannerApps, scanned, fleetFiled)
	if why != "" {
		logf("retired: %s", why)
		return
	}
	if len(retire) == 0 {
		logf("retired: every open AppSec ticket's application is still in the scanner")
		return
	}
	for _, r := range retire {
		logf("retired: %s (%s) - application id %s is no longer in the scanner",
			r.Issue.Key, safelog.Line(oneLine(r.Issue.Fields.Summary, 80)), r.AppID)
		closeTicket(ctx, c, cfg, r.Issue, retireComment(r.Issue, r.AppID, now), forReal)
	}
}

// doAppscanCloseTest is the single labelled real test of closing: it closes
// ONE ticket, and only one filed by --appscan-test (label cti-agent-test, and
// not one of the weekly run's tickets). Preview unless --for-real.
func doAppscanCloseTest(ctx context.Context, c *jira.Client, cfg config.Config, key string, forReal bool) int {
	jql := fmt.Sprintf(`project = %q AND key = %q AND labels = %q AND statusCategory != Done`,
		cfg.JiraProjectKey, key, appscanTestLabel)
	hits, err := c.Search(ctx, jql, 2)
	if err != nil {
		return die("searching for %s failed: %s", safelog.Line(key), safelog.Line(err.Error()))
	}
	if len(hits) != 1 || hits[0].Key != key {
		return die("%s is not an open ticket in project %s labelled %s - this test closes only "+
			"tickets filed by --appscan-test", safelog.Line(key), safelog.Line(cfg.JiraProjectKey), appscanTestLabel)
	}
	for _, l := range hits[0].Fields.Labels {
		if l == appscanLabel {
			return die("%s is one of the weekly run's tickets; this test will not close it", safelog.Line(key))
		}
	}
	comment := "*TEST* - closed by cti-jira --appscan-close-test to show how the AppSec lane closes the " +
		"ticket of a retired application."
	switch closeTicket(ctx, c, cfg, hits[0], comment, forReal) {
	case closed, wouldClose:
		if !forReal {
			logf("appscan-close-test: DRY RUN - nothing changed. Add --for-real to close it.")
		}
		return exitOK
	case closeGated:
		return exitFailure
	}
	return exitFailure
}
