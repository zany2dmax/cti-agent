package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// listMax bounds one listing. Reaching it is said, not hidden.
const listMax = 200

// fleetLabel marks every real fleet ticket (a test ticket has cti-agent-test instead).
const fleetLabel = "cti-agent"

// listJQL selects every ticket the fleet filed in the project: the real
// marker label or the test one. Open only unless all.
func listJQL(projectKey string, all bool) string {
	q := fmt.Sprintf(`project = %q AND (labels = %q OR labels = %q)`,
		projectKey, fleetLabel, appscanTestLabel)
	if !all {
		q += ` AND statusCategory != Done`
	}
	return q + ` ORDER BY created ASC`
}

// ticketKind names a ticket from the labels the fleet set on it.
func ticketKind(labels []string) string {
	var cve, app, dom bool
	for _, l := range labels {
		l = strings.ToLower(strings.TrimSpace(l))
		switch {
		case l == appscanTestLabel:
			return "test"
		case strings.HasPrefix(l, "cti-cve-"):
			cve = true
		case l == appscanLabel:
			app = true
		case l == domainsLabel:
			dom = true
		}
	}
	switch {
	case cve:
		return "CVE"
	case app:
		return "AppSec"
	case dom:
		return "lock-down"
	}
	return "other"
}

type listRow struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Done     bool   `json:"done"`
	AgeDays  int    `json:"age_days"`
	Assignee string `json:"assignee"`
	Kind     string `json:"kind"`
	Summary  string `json:"summary"`
}

func parseJiraTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.000-0700", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// doList prints the fleet's tickets. It only reads: no mode, no write gate.
// Every text field comes from Jira, where a person or a scanner wrote it, so
// each is sanitised before it reaches a terminal (and in JSON too, so the
// output is the same text either way).
func doList(ctx context.Context, c *jira.Client, cfg config.Config, all, asJSON bool,
	out io.Writer, now time.Time) int {

	issues, err := c.Search(ctx, listJQL(cfg.JiraProjectKey, all), listMax)
	if err != nil {
		return die("listing tickets failed: %s", safelog.Line(err.Error()))
	}
	rows := make([]listRow, 0, len(issues))
	for _, i := range issues {
		r := listRow{
			Key:      safelog.Line(i.Key),
			Status:   safelog.Line(i.Fields.Status.Name),
			Done:     i.IsDone(),
			Assignee: "unassigned",
			Kind:     ticketKind(i.Fields.Labels),
			Summary:  safelog.Line(i.Fields.Summary),
		}
		if i.Fields.Assignee != nil && i.Fields.Assignee.DisplayName != "" {
			r.Assignee = safelog.Line(i.Fields.Assignee.DisplayName)
		}
		if t, ok := parseJiraTime(i.Fields.Created); ok {
			r.AgeDays = int(now.Sub(t).Hours() / 24)
		} else {
			r.AgeDays = -1
		}
		rows = append(rows, r)
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return die("writing the listing: %s", err.Error())
		}
		return exitOK
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "KEY\tSTATUS\tAGE\tASSIGNEE\tKIND\tSUMMARY")
	for _, r := range rows {
		age := "?"
		if r.AgeDays >= 0 {
			age = fmt.Sprintf("%dd", r.AgeDays)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Key, r.Status, age, r.Assignee, r.Kind, r.Summary)
	}
	_ = tw.Flush()
	if len(rows) == 0 {
		_, _ = fmt.Fprintln(out, "no fleet tickets found")
	}
	if len(issues) >= listMax {
		_, _ = fmt.Fprintf(out, "NOTE: showing the first %d; there may be more\n", listMax)
	}
	return exitOK
}
