package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/domains"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// ONE LOCK-DOWN TICKET, NOT ONE PER DOMAIN
//
// Every change the domains lane asks for is a DNS record at the registrar,
// and every one needs the same GoDaddy admin access - so it is one piece of
// work for one person, and one ticket. Per-domain tickets would put sixty
// near-identical items in IT's queue for an afternoon's job.
//
// The cadence: while a fleet lock-down ticket is open, each week's run adds a
// comment ONLY when the list of changes is different from the last one it
// posted (the hash is kept on the ticket as an issue property). A new ticket
// is filed only when none is open. When nothing is left to change, the open
// ticket is told so once.

const (
	domainsLabel   = "cti-domains-lockdown"
	domainsPropKey = "cti-domains-lockdown"
)

// domainsState is kept on the ticket.
type domainsState struct {
	Hash     string    `json:"hash"`
	PostedAt time.Time `json:"postedAt"`
	Exact    int       `json:"exact"`
	Review   int       `json:"review"`
	// Resolved: the ticket has been told nothing is left, so an empty list
	// next week says nothing more.
	Resolved bool `json:"resolved,omitempty"`
}

func domainsJQL(projectKey string) string {
	return fmt.Sprintf(`project = %q AND labels = %q AND statusCategory != Done ORDER BY created DESC`,
		projectKey, domainsLabel)
}

func doDomainsActions(ctx context.Context, c *jira.Client, cfg config.Config,
	path string, forReal bool, now time.Time, refOut string) int {

	// What happened, for the email. Written on every path, failures
	// included: "not updated, and why" is worth saying in the report.
	ref := func(action string, is *jira.Issue, note string) {
		if refOut == "" {
			return
		}
		r := domains.TicketRef{Action: action, Note: note}
		if is != nil {
			r.Key, r.URL, r.Status = is.Key, c.BrowseURL(is.Key), is.Fields.Status.Name
		}
		if err := domains.WriteTicketRef(refOut, r); err != nil {
			logf("WARNING: could not write %s: %s", safelog.Line(refOut), safelog.Line(err.Error()))
		}
	}

	// path is the operator- or runner-supplied --domains-actions file.
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path, read-only
	if err != nil {
		return die("reading %s: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	var af domains.ActionsFile
	if err := json.Unmarshal(b, &af); err != nil {
		return die("%s is not a cti-domains actions file: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	logf("domains: %d exact change(s), %d to review, on %d domain(s) (list %s)",
		af.Exact, af.Review, af.Domains, af.Hash)

	issues, err := c.Search(ctx, domainsJQL(cfg.JiraProjectKey), 5)
	if err != nil {
		ref("error", nil, "Jira could not be searched for the open ticket")
		return die("searching for an open lock-down ticket: %s", safelog.Line(err.Error()))
	}
	var open *jira.Issue
	if len(issues) > 0 {
		open = &issues[0]
		if len(issues) > 1 {
			logf("note   : %d open lock-down tickets; updating the newest, %s", len(issues), open.Key)
		}
	}

	var prev domainsState
	if open != nil {
		if _, err := c.GetProperty(ctx, open.Key, domainsPropKey, &prev); err != nil {
			// Unknown is not "never posted": commenting now would repeat the
			// same list on the ticket whenever Jira had a bad minute.
			logf("WARNING: could not read what %s was last told (%s) - leaving it alone this run",
				open.Key, safelog.Line(err.Error()))
			ref("error", open, "could not read what it was last told, so it was left alone")
			return exitOK
		}
	}

	plan, why := planDomains(open, prev, af)
	logf("domains: %s", why)
	if plan == domainsNothing {
		switch {
		case open == nil:
			ref("none", nil, "")
		case prev.Resolved && len(af.Actions) == 0:
			ref("resolved", open, "")
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
		logf("DRY RUN - nothing written to Jira. Add --for-real to %s.", plan)
		if plan == domainsCreate || plan == domainsComment {
			fmt.Println(domainsBody(af, now))
		}
		return exitOK
	}
	if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
		logf("WRITE GATE CLOSED - lock-down ticket not %s: %s", plan, safelog.Line(err.Error()))
		ref("gate-closed", open, "the Jira write gate is closed (JIRA_ALLOW_CREATE)")
		return exitOK
	}

	csvName := fmt.Sprintf("domains-dns-changes-%s.csv", now.Format("2006-01-02"))
	csvBody := domains.ActionsCSV(af.Actions)
	st := domainsState{Hash: af.Hash, PostedAt: now, Exact: af.Exact, Review: af.Review}

	switch plan {
	case domainsCreate:
		res, err := c.CreateIssue(ctx, jira.IssueRequest{
			ProjectKey:  cfg.JiraProjectKey,
			IssueType:   cfg.JiraIssueType,
			Summary:     domainsSummary(af, now),
			Description: domainsBody(af, now),
			Labels:      []string{"cti-agent", domainsLabel},
		})
		if err != nil {
			ref("error", nil, "Jira refused to create it")
			return die("creating the lock-down ticket: %s", safelog.Line(err.Error()))
		}
		if err := c.Attach(ctx, res.Key, csvName, csvBody); err != nil {
			logf("WARNING: %s was created but the CSV did not attach: %s", res.Key, safelog.Line(err.Error()))
		}
		if err := c.SetProperty(ctx, res.Key, domainsPropKey, st); err != nil {
			logf("WARNING: could not record the list on %s - next week will comment again: %s",
				res.Key, safelog.Line(err.Error()))
		}
		logf("filed %s - %s", res.Key, c.BrowseURL(res.Key))
		created := &jira.Issue{Key: res.Key}
		ref("created", created, "")
		emit(map[string]any{"mode": "for-real", "action": "created", "key": res.Key, "url": c.BrowseURL(res.Key)})

	case domainsComment:
		text := "The weekly domains check found a different list of DNS changes. " +
			"This replaces the list above.\n\n" + domainsBody(af, now)
		if err := c.AddComment(ctx, open.Key, text); err != nil {
			ref("error", open, "the comment with this week's list was refused")
			return die("commenting on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		if err := c.Attach(ctx, open.Key, csvName, csvBody); err != nil {
			logf("WARNING: comment posted but the CSV did not attach: %s", safelog.Line(err.Error()))
		}
		if err := c.SetProperty(ctx, open.Key, domainsPropKey, st); err != nil {
			logf("WARNING: could not record the list on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		logf("commented on %s with the updated list", open.Key)
		ref("commented", open, "")
		emit(map[string]any{"mode": "for-real", "action": "commented", "key": open.Key, "url": c.BrowseURL(open.Key)})

	case domainsDone:
		text := fmt.Sprintf("The weekly domains check on %s found every domain matching its "+
			"profile: nothing in this ticket is left to change. It can be closed.", now.Format("2 January 2006"))
		if err := c.AddComment(ctx, open.Key, text); err != nil {
			ref("error", open, "the closing comment was refused")
			return die("commenting on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		st.Resolved = true
		if err := c.SetProperty(ctx, open.Key, domainsPropKey, st); err != nil {
			logf("WARNING: could not record the list on %s: %s", open.Key, safelog.Line(err.Error()))
		}
		logf("told %s that nothing is left to change", open.Key)
		ref("resolved", open, "")
		emit(map[string]any{"mode": "for-real", "action": "resolved", "key": open.Key, "url": c.BrowseURL(open.Key)})
	}
	return exitOK
}

type domainsPlan string

const (
	domainsNothing domainsPlan = "do nothing"
	domainsCreate  domainsPlan = "file a new lock-down ticket"
	domainsComment domainsPlan = "comment the updated list on the open ticket"
	domainsDone    domainsPlan = "tell the open ticket nothing is left"
)

// planDomains decides, without touching Jira. Pure, so it is tested.
func planDomains(open *jira.Issue, prev domainsState, af domains.ActionsFile) (domainsPlan, string) {
	empty := len(af.Actions) == 0
	switch {
	case open == nil && empty:
		return domainsNothing, "no changes needed and no lock-down ticket open"
	case open == nil:
		return domainsCreate, "no lock-down ticket is open"
	case empty && prev.Resolved:
		return domainsNothing, fmt.Sprintf("%s already told nothing is left", open.Key)
	case empty:
		return domainsDone, fmt.Sprintf("every change on %s is done", open.Key)
	case prev.Hash == af.Hash:
		return domainsNothing, fmt.Sprintf("%s already has this exact list (posted %s) - no comment",
			open.Key, prev.PostedAt.Format("2006-01-02"))
	}
	return domainsComment, fmt.Sprintf("%s is open and the list has changed", open.Key)
}

func domainsSummary(af domains.ActionsFile, now time.Time) string {
	return fmt.Sprintf("Domain DNS lock-down: %d change(s) on %d domain(s) - week of %s",
		af.Exact+af.Review, af.Domains, now.Format("2006-01-02"))
}

// domainsBody is the ticket text, Jira wiki markup (the v2 API's format).
func domainsBody(af domains.ActionsFile, now time.Time) string {
	var b strings.Builder
	b.WriteString("Filed automatically by the CTI agent's weekly domains check. Every change " +
		"below is a DNS record at the registrar and needs GoDaddy DNS admin access, so they " +
		"are one ticket.\n\n")
	b.WriteString("*Exact changes* can be applied as written. *To review* needs a decision " +
		"first - usually who really sends mail as the domain. The attached CSV has the same " +
		"list. The check runs weekly and comments here when the list changes.\n\n")
	b.WriteString("*Before setting a null MX* (MX {{0 .}}), confirm no mailbox, alias or " +
		"forwarder uses the domain: it makes every sender's mail to it fail at once.\n\n")

	section := func(title string, exact bool) {
		var lines []string
		last := ""
		for _, x := range af.Actions {
			if x.Exact() != exact {
				continue
			}
			if x.Domain != last {
				lines = append(lines, fmt.Sprintf("\n*%s* (%s)", wikiEscape(x.Domain), wikiEscape(x.Profile)))
				last = x.Domain
			}
			lines = append(lines, "* "+wikiAction(x))
		}
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&b, "h3. %s\n%s\n\n", title, strings.Join(lines, "\n"))
	}
	section(fmt.Sprintf("Exact changes (%d)", af.Exact), true)
	section(fmt.Sprintf("To review (%d)", af.Review), false)
	fmt.Fprintf(&b, "_Generated %s; list %s._", now.UTC().Format("2006-01-02 15:04 UTC"), af.Hash)
	return b.String()
}

func wikiAction(x domains.Action) string {
	rec := fmt.Sprintf("%s {{%s}}", x.Type, wikiEscape(x.Host))
	switch {
	case x.Delete:
		return fmt.Sprintf("%s: *delete* - %s", rec, wikiEscape(x.Why))
	case x.Set != "" && x.Replace != "":
		return fmt.Sprintf("%s: replace {{%s}} with {{%s}} - %s", rec,
			wikiEscape(x.Replace), wikiEscape(x.Set), wikiEscape(x.Why))
	case x.Set != "":
		return fmt.Sprintf("%s: add {{%s}} - %s", rec, wikiEscape(x.Set), wikiEscape(x.Why))
	}
	cur := ""
	if x.Replace != "" {
		cur = fmt.Sprintf(" (now {{%s}})", wikiEscape(x.Replace))
	}
	return fmt.Sprintf("%s%s: %s", rec, cur, wikiEscape(x.Why))
}

// wikiEscape keeps a value from being read as wiki markup: braces end a
// {{monospace}} span, brackets make a link, a pipe a table cell, "!" an
// embedded image, and * _ + ^ ~ ? - format text. Values from DNS and from
// the scanner both pass through here; see wikiMarkup.
func wikiEscape(s string) string {
	return wikiMarkup.Replace(strings.Join(strings.Fields(s), " "))
}

func modeName(forReal bool) string {
	if forReal {
		return "for-real"
	}
	return "dry-run"
}
