package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// ONE TEST TICKET FOR ONE APPLICATION
//
//	cti-jira --appscan-tickets T.json --appscan-test 1234 [--appscan-reports D]            # preview
//	cti-jira --appscan-tickets T.json --appscan-test 1234 [--appscan-reports D] --for-real # file it
//
// What a developer would get for that application - the same summary, body,
// findings attachment and scanner report - filed as a NEW ticket that the
// lane can never mistake for the real one:
//
//   - labelled cti-agent-test only: no cti-agent label (the follow-up skips
//     it) and no per-application label (the weekly run never finds it, so it
//     is never commented on and never stands in for the real ticket);
//   - "[TEST]" at the front of the summary and a banner in the body;
//   - no assignee, no component, no watchers: the fleet notifies nobody
//     (Jira's own notification scheme or a default assignee still may);
//   - no state property: it is not part of any week-over-week diff.
//
// It never searches for, comments on or changes an existing ticket. The
// Jira write gate (JIRA_ALLOW_CREATE) applies as it does to every create.

// appscanTestLabel marks a test ticket. Shared with --test-ticket.
const appscanTestLabel = "cti-agent-test"

func doAppscanTest(ctx context.Context, c *jira.Client, cfg config.Config, path, appID, reportsDir string,
	forReal bool, now time.Time) int {

	t, err := testTicketFor(path, appID)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	name := safelog.Line(t.App)
	rep, hasRep, repName := loadAppReport(t, true, reportsDir, now, name)
	file := fmt.Sprintf("appscan-%s.txt", now.Format("2006-01-02"))
	full := []byte(appscanFullText(t, now))

	summary := "[TEST] " + appscanSummary(t)
	body := "*TEST TICKET* - filed by cti-jira --appscan-test to show what a developer receives " +
		"for this application. It is not tracked by the weekly run and the fleet notified nobody; " +
		"delete it when you are done.\n\n" + appscanBody(t, now) + reportNote(hasRep, repName)

	if !forReal {
		// stdout: the runner or operator keeps it in a 0600 file - it names
		// URLs and parameters on our own application.
		fmt.Printf("===== would create TEST ticket for %s\nsummary: %s\nlabels: %s\n%s\n%s",
			oneLine(t.App, 80), summary, appscanTestLabel, body,
			attachPreview(hasRep, repName, rep.Body, file, full))
		logf("appscan-test: DRY RUN - nothing created. Add --for-real to file it.")
		return exitOK
	}
	if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	res, err := c.CreateIssue(ctx, jira.IssueRequest{
		ProjectKey:  cfg.JiraProjectKey,
		IssueType:   cfg.JiraIssueType,
		Summary:     summary,
		Description: body,
		Labels:      []string{appscanTestLabel},
	})
	if err != nil {
		return die("creating the test ticket: %s", safelog.Line(err.Error()))
	}
	logf("appscan-test: created %s - %s", res.Key, c.BrowseURL(res.Key))
	rc := exitOK
	if err := c.Attach(ctx, res.Key, file, full); err != nil {
		logf("WARNING: %s created but %s did not attach: %s", res.Key, file, safelog.Line(err.Error()))
		rc = exitFailure
	} else {
		logf("appscan-test: attached %s (%s)", file, kb(len(full)))
	}
	if hasRep {
		if err := c.Attach(ctx, res.Key, repName, rep.Body); err != nil {
			logf("WARNING: %s created but the scanner report did not attach: %s", res.Key, safelog.Line(err.Error()))
			rc = exitFailure
		} else {
			logf("appscan-test: attached %s (%s)", repName, kb(len(rep.Body)))
		}
	} else {
		logf("appscan-test: no scanner report for this application in --appscan-reports - none attached")
	}
	logf("appscan-test: delete %s when you are done with it", res.Key)
	return rc
}

// testTicketFor picks one application out of a tickets file by its scanner
// web-app id. One that the weekly run would leave alone is refused: its
// ticket would say nothing useful.
func testTicketFor(path, appID string) (appscan.AppTicket, error) {
	id := strings.TrimSpace(appID)
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the operator's own cti-appscan --tickets-out file
	if err != nil {
		return appscan.AppTicket{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var tf appscan.TicketsFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return appscan.AppTicket{}, fmt.Errorf("%s is not a cti-appscan tickets file: %w", path, err)
	}
	var ids []string
	for _, t := range tf.Tickets {
		if t.AppID == id {
			if t.Skip != "" {
				return appscan.AppTicket{}, fmt.Errorf("web app %s is in the file but the weekly run would leave it alone: %s", id, t.Skip)
			}
			return t, nil
		}
		if t.AppID != "" {
			ids = append(ids, t.AppID)
		}
	}
	return appscan.AppTicket{}, fmt.Errorf("web app %s is not in %s (it has: %s)", id, path, strings.Join(ids, ", "))
}
