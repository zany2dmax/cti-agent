package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/vmscan"
)

// ONE SPREADSHEET TICKET FOR THE NETWORK TEAM
//
// The VM scan lane's coverage check lists the rows of the network spreadsheet
// that cannot be read as written. The spreadsheet is the network team's, so
// those go to them - as ONE ticket in the help desk's project, unassigned, for
// the help desk to route, filed by the fleet. The same cadence as the domains
// lock-down ticket: a new ticket only when none is open, a comment only when
// the list has changed (its hash is kept on the ticket), and one "nothing is
// left" comment when the list empties. A held list (the coverage check did
// not run) touches nothing.

const (
	vmscanFixesLabel   = "cti-vmscan-sheet-fixes"
	vmscanFixesPropKey = "cti-vmscan-sheet-fixes"
)

type vmscanFixesState struct {
	Hash     string    `json:"hash"`
	PostedAt time.Time `json:"postedAt"`
	Count    int       `json:"count"`
	Resolved bool      `json:"resolved,omitempty"`
}

func vmscanFixesJQL(projectKey string) string {
	return fmt.Sprintf(`project = %q AND labels = %q AND %s AND statusCategory != Done ORDER BY created DESC`,
		projectKey, vmscanFixesLabel, jira.ReporterClause())
}

func doVMScanFixes(ctx context.Context, c *jira.Client, cfg config.Config,
	path string, forReal bool, now time.Time, refOut string) int {

	// What happened, for the weekly report (cti-vmscan --stamp-ticket).
	// Written on every path that reaches Jira, failures included: "not
	// updated, and why" is worth saying in the report.
	ref := func(action string, is *jira.Issue, note string) {
		if refOut == "" {
			return
		}
		r := vmscan.TicketRef{Action: action, Note: note}
		if is != nil {
			r.Key, r.URL, r.Status = is.Key, c.BrowseURL(is.Key), is.Fields.Status.Name
		}
		if err := vmscan.WriteTicketRef(refOut, r); err != nil {
			logf("WARNING: could not write %s: %s", safelog.Line(refOut), safelog.Line(err.Error()))
		}
	}

	// path is the runner-supplied --vmscan-fixes file.
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path, read-only
	if err != nil {
		return die("reading %s: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	var ff vmscan.FixesFile
	if err := json.Unmarshal(b, &ff); err != nil {
		return die("%s is not a cti-vmscan fixes file: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	project := cfg.VMScanProject()
	if strings.TrimSpace(project) == "" {
		ref("error", nil, "no Jira project is configured")
		return die("no Jira project: set JIRA_PROJECT_KEY (or JIRA_VMSCAN_PROJECT_KEY)")
	}
	logf("vmscan: %d spreadsheet row(s) to correct and %d to clean up, for the network team (list %s)",
		len(ff.Fixes), len(ff.Cleanup), ff.Hash)

	issues, err := c.Search(ctx, vmscanFixesJQL(project), 5)
	if err != nil {
		ref("error", nil, "Jira could not be searched for the open ticket")
		return die("searching for an open spreadsheet ticket: %s", safelog.Line(err.Error()))
	}
	var open *jira.Issue
	if len(issues) > 0 {
		open = &issues[0]
		if len(issues) > 1 {
			logf("note   : %d open spreadsheet tickets; updating the newest, %s", len(issues), open.Key)
		}
	}
	var prev vmscanFixesState
	if open != nil {
		if _, err := c.GetProperty(ctx, open.Key, vmscanFixesPropKey, &prev); err != nil {
			// Unknown is not "never posted": commenting now could repeat the list.
			logf("WARNING: could not read what %s was last told (%s) - leaving it alone this run",
				open.Key, safelog.Line(err.Error()))
			ref("error", open, "could not read what it was last told, so it was left alone")
			return exitOK
		}
	}

	plan, why := planVMScanFixes(open, prev, ff)
	logf("vmscan: %s", why)
	if plan == domainsNothing {
		switch {
		case ff.Held:
			ref("held", open, "")
		case open == nil:
			ref("none", nil, "")
		case prev.Resolved:
			ref("resolved-earlier", open, "")
		default:
			ref("unchanged", open, "")
		}
		emit(map[string]any{"mode": modeName(forReal), "action": "nothing", "reason": why})
		return exitOK
	}
	if !forReal {
		switch plan {
		case domainsCreate:
			ref("would-create", nil, "")
		case domainsComment:
			ref("would-comment", open, "")
		case domainsDone:
			ref("would-resolve", open, "")
		}
		logf("DRY RUN - nothing written to Jira. Add --for-real to %s.", vmscanPlanWords(plan))
		if plan != domainsDone {
			fmt.Println(vmscanFixesSummary(ff, now))
			fmt.Println(vmscanFixesBody(ff, now))
		}
		return exitOK
	}
	if err := jira.CheckAllowed(project, cfg.JiraAllowCreate); err != nil {
		logf("WRITE GATE CLOSED - spreadsheet ticket not written: %s", safelog.Line(err.Error()))
		ref("gate-closed", open, "the Jira write gate is closed (JIRA_ALLOW_CREATE)")
		return exitOK
	}

	st := vmscanFixesState{Hash: ff.Hash, PostedAt: now, Count: len(ff.Fixes) + len(ff.Cleanup)}
	switch plan {
	case domainsCreate:
		res, err := c.CreateIssue(ctx, jira.IssueRequest{
			ProjectKey:  project,
			IssueType:   cfg.VMScanIssueType(),
			Summary:     vmscanFixesSummary(ff, now),
			Description: vmscanFixesBody(ff, now),
			Labels:      []string{"cti-agent", vmscanFixesLabel},
		})
		var cont *jira.ContinuationError
		if errors.As(err, &cont) {
			logf("WARNING: %s", safelog.Line(err.Error()))
			err = nil
		}
		if err != nil {
			ref("error", nil, "Jira refused to create it")
			return die("creating the spreadsheet ticket: %s", safelog.Line(err.Error()))
		}
		if err := c.SetProperty(ctx, res.Key, vmscanFixesPropKey, st); err != nil {
			logf("WARNING: could not record the list on %s - next week will comment again: %s",
				res.Key, safelog.Line(err.Error()))
		}
		logf("filed %s - %s", res.Key, c.BrowseURL(res.Key))
		ref("created", &jira.Issue{Key: res.Key}, "")
		emit(map[string]any{"mode": "for-real", "action": "created", "key": res.Key, "url": c.BrowseURL(res.Key)})

	case domainsComment:
		text := "The weekly VM scan coverage check found a different list of spreadsheet rows to " +
			"correct. This replaces the list above.\n\n" + vmscanFixesBody(ff, now)
		if err := c.AddComment(ctx, open.Key, text); err != nil {
			ref("error", open, "the comment with this week's list was refused")
			return die("commenting on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		if err := c.SetProperty(ctx, open.Key, vmscanFixesPropKey, st); err != nil {
			logf("WARNING: could not record the list on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		logf("commented on %s with the updated list", open.Key)
		ref("commented", open, "")
		emit(map[string]any{"mode": "for-real", "action": "commented", "key": open.Key, "url": c.BrowseURL(open.Key)})

	case domainsDone:
		text := fmt.Sprintf("The weekly VM scan coverage check on %s could read every location in the "+
			"network spreadsheet and found nothing to clean up: nothing in this ticket is left. It can be closed.",
			now.Format("2 January 2006"))
		if err := c.AddComment(ctx, open.Key, text); err != nil {
			ref("error", open, "the closing comment was refused")
			return die("commenting on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		st.Resolved = true
		if err := c.SetProperty(ctx, open.Key, vmscanFixesPropKey, st); err != nil {
			logf("WARNING: could not record the list on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		logf("told %s that nothing is left to correct", open.Key)
		ref("resolved", open, "")
		emit(map[string]any{"mode": "for-real", "action": "resolved", "key": open.Key, "url": c.BrowseURL(open.Key)})
	}
	return exitOK
}

func vmscanPlanWords(p domainsPlan) string {
	switch p {
	case domainsCreate:
		return "file a new spreadsheet ticket"
	case domainsComment:
		return "comment the updated list on the open ticket"
	case domainsDone:
		return "tell the open ticket nothing is left"
	}
	return string(p)
}

// planVMScanFixes decides, without touching Jira. Pure, so it is tested.
func planVMScanFixes(open *jira.Issue, prev vmscanFixesState, ff vmscan.FixesFile) (domainsPlan, string) {
	empty := len(ff.Fixes) == 0 && len(ff.Cleanup) == 0
	switch {
	case ff.Held:
		return domainsNothing, "held: " + ff.HeldWhy + " - nothing is filed, changed or resolved"
	case open == nil && empty:
		return domainsNothing, "nothing to correct and no spreadsheet ticket open"
	case open == nil:
		return domainsCreate, "no spreadsheet ticket is open"
	case empty && prev.Resolved:
		return domainsNothing, fmt.Sprintf("%s already told nothing is left", open.Key)
	case empty:
		return domainsDone, fmt.Sprintf("every row on %s is corrected", open.Key)
	case prev.Hash == ff.Hash:
		return domainsNothing, fmt.Sprintf("%s already has this exact list (posted %s) - no comment",
			open.Key, prev.PostedAt.Format("2006-01-02"))
	}
	return domainsComment, fmt.Sprintf("%s is open and the list has changed", open.Key)
}

func vmscanFixesSummary(ff vmscan.FixesFile, now time.Time) string {
	return fmt.Sprintf("Network spreadsheet: %d location(s) to correct, %d item(s) to clean up - week of %s",
		len(ff.Fixes), len(ff.Cleanup), now.Format("2006-01-02"))
}

// writeFixGroups writes items grouped under their titles, a blank line before
// each heading so Jira cannot run the list above into it.
func writeFixGroups(b *strings.Builder, fixes []vmscan.SheetFix) {
	last := ""
	for _, x := range fixes {
		if x.Title != last {
			if last != "" {
				b.WriteString("\n")
			}
			fmt.Fprintf(b, "h3. %s\n%s\n\n", wikiEscape(x.Title), wikiEscape(x.Action))
			last = x.Title
		}
		row := ""
		if x.Row > 0 {
			row = fmt.Sprintf(" (sheet row %d)", x.Row)
		}
		fmt.Fprintf(b, "* *%s*%s: %s\n", wikiEscape(x.Location), row, wikiEscape(x.Problem))
	}
}

// vmscanFixesBody is the ticket text, Jira wiki markup (the v2 API's format).
// Location names come from the spreadsheet, so they are escaped.
func vmscanFixesBody(ff vmscan.FixesFile, now time.Time) string {
	var b strings.Builder
	b.WriteString("Filed automatically by the CTI agent's weekly VM scan coverage check, for the " +
		"help desk to assign to the network team. The check compares the network spreadsheet " +
		"with what the scanner scans; the locations below cannot be " +
		"read as written, so they are not checked until they are corrected; the clean-up items " +
		"do not stop the check, but the sheet is wrong or unclear there. Each line names the " +
		"sheet row. The check runs weekly and comments here only when the list changes.\n\n")
	if len(ff.Fixes) > 0 {
		b.WriteString("h2. To correct (the check cannot read these)\n\n")
		writeFixGroups(&b, ff.Fixes)
	}
	if len(ff.Cleanup) > 0 {
		if len(ff.Fixes) > 0 {
			b.WriteString("\n")
		}
		b.WriteString("h2. Clean-up (does not stop the check)\n\n")
		writeFixGroups(&b, ff.Cleanup)
	}
	fmt.Fprintf(&b, "\n_Generated %s; list %s._", now.UTC().Format("2006-01-02 15:04 UTC"), ff.Hash)
	return b.String()
}
