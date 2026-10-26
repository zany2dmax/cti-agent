package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/ticketref"
)

// ONE TICKET PER APPLICATION (see internal/appscan/tickets.go)
//
// The lifecycle is the domains lock-down ticket's, per application:
//
//   - no open ticket and findings      -> file one, assigned to the owner
//   - open ticket, findings changed    -> comment: what is new, what is gone
//   - open ticket, same findings       -> nothing (no weekly noise)
//   - open ticket, nothing left        -> say so once; a person closes it
//   - scan faulty or detail missing    -> touch nothing (Skip)
//
// The ticket is found by its own label (cti-appscan-<app id>), and what it
// was last told is kept on it as an issue property, so a reassigned, edited
// or re-labelled ticket is still the same ticket next week.

const (
	appscanLabel   = "cti-appscan"
	appscanPropKey = "cti-appscan"
	// maxBody keeps a description or comment under Jira's 32,767-character
	// limit with room for the wrapper text. What does not fit is in the
	// attachment, which always carries the full list.
	maxBody = 28000
	// hardMax is Jira's own limit on a description or comment, less a margin.
	hardMax = 32000
	// maxKeys bounds the fingerprints kept on the ticket. Each is QID plus a
	// short hash (about 20 bytes as JSON), so 1,200 stays well inside Jira Cloud's
	// 32 KB issue-property limit; a list cut short only over-counts "new".
	maxKeys = 1200
	// maxField bounds a URL or parameter in ticket text: a scanned path can
	// be kilobytes, and the full one is in the attachment.
	maxField = 300
)

// stateKey is what is kept on the ticket for one place a finding was seen:
// the QID in clear (so "no longer detected" can name it) and a hash of the
// URL and parameter.
func stateKey(instanceKey string) string {
	qid := instanceKey
	if i := strings.Index(instanceKey, "|"); i >= 0 {
		qid = instanceKey[:i]
	}
	sum := sha256.Sum256([]byte(instanceKey))
	return qid + ":" + hex.EncodeToString(sum[:])[:10]
}

func stateKeys(t appscan.AppTicket) []string {
	var out []string
	for _, k := range t.InstanceKeys() {
		out = append(out, stateKey(k))
	}
	sort.Strings(out)
	if len(out) > maxKeys {
		out = out[:maxKeys]
	}
	return out
}

// appscanState is kept on each ticket.
type appscanState struct {
	Hash     string    `json:"hash"`
	Keys     []string  `json:"keys"`
	PostedAt time.Time `json:"postedAt"`
	Resolved bool      `json:"resolved,omitempty"`
}

// AppscanRefs is cti-jira --appscan-tickets --ref-out: one ref per
// application key.
type AppscanRefs struct {
	Apps map[string]ticketref.Ref `json:"apps"`
}

func appscanJQL(projectKey, label string) string {
	return fmt.Sprintf(`project = %q AND labels = %q AND statusCategory != Done ORDER BY created DESC`,
		projectKey, label)
}

// priorJQL finds this application's most recent CLOSED ticket, for a new
// ticket to point back to when the findings return.
func priorJQL(projectKey, label string) string {
	return fmt.Sprintf(`project = %q AND labels = %q AND statusCategory = Done ORDER BY created DESC`,
		projectKey, label)
}

// priorTicket is a resolved or closed ticket for the same application.
type priorTicket struct {
	Key    string
	Status string
	Back   int // findings on the new ticket that were also on this one when it was last told
}

// findPrior looks for the application's last closed ticket. Best effort: a
// failure costs the back-reference, never the new ticket.
func findPrior(ctx context.Context, c *jira.Client, cfg config.Config, label string,
	t appscan.AppTicket, name string) *priorTicket {
	issues, err := c.Search(ctx, priorJQL(cfg.JiraProjectKey, label), 1)
	if err != nil {
		logf("appscan: %s: could not look for an earlier closed ticket: %s", name, safelog.Line(err.Error()))
		return nil
	}
	if len(issues) == 0 {
		return nil
	}
	p := &priorTicket{Key: issues[0].Key, Status: issues[0].Fields.Status.Name}
	var st appscanState
	if found, err := c.GetProperty(ctx, p.Key, appscanPropKey, &st); err == nil && found {
		was := map[string]bool{}
		for _, k := range st.Keys {
			was[k] = true
		}
		for _, k := range stateKeys(t) {
			if was[k] {
				p.Back++
			}
		}
	}
	return p
}

// priorNote is the line on a new ticket that names the closed one before it.
func priorNote(p *priorTicket) string {
	if p == nil {
		return ""
	}
	s := fmt.Sprintf("\n\n*Recurring:* this application's previous ticket, %s, is %s.",
		wikiEscape(p.Key), wikiEscape(oneLine(p.Status, 40)))
	if p.Back > 0 {
		s += fmt.Sprintf(" %d of the findings below were on it when it was last updated - they are back, "+
			"or were never fixed.", p.Back)
	}
	return s
}

type appPlan string

const (
	appNothing appPlan = "do nothing"
	appCreate  appPlan = "file a new ticket"
	appComment appPlan = "comment the changed findings"
	appDone    appPlan = "tell the ticket nothing is left"
)

// planApp decides, without touching Jira. Pure, so it is tested.
func planApp(open *jira.Issue, prev appscanState, t appscan.AppTicket) (appPlan, string) {
	empty := len(t.Findings) == 0
	switch {
	case open == nil && empty:
		return appNothing, "nothing of Serious or above open, and no ticket"
	case open == nil:
		return appCreate, "no ticket is open"
	case empty && prev.Resolved:
		return appNothing, open.Key + " already told nothing is left"
	case empty:
		return appDone, "nothing of Serious or above is left on " + open.Key
	case prev.Hash == t.Hash:
		return appNothing, fmt.Sprintf("%s already has these findings (posted %s)",
			open.Key, prev.PostedAt.Format("2006-01-02"))
	}
	return appComment, open.Key + " is open and its findings changed"
}

func doAppscanTickets(ctx context.Context, c *jira.Client, cfg config.Config,
	path string, forReal bool, now time.Time, refOut, reportsDir string) int {

	refs := AppscanRefs{Apps: map[string]ticketref.Ref{}}
	save := func() {
		if refOut == "" {
			return
		}
		if err := ticketref.Write(refOut, refs); err != nil {
			logf("WARNING: could not write %s: %s", safelog.Line(refOut), safelog.Line(err.Error()))
		}
	}
	defer save()

	b, err := os.ReadFile(path) // #nosec G304 -- the runner's own --tickets-out file
	if err != nil {
		return die("reading %s: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	var tf appscan.TicketsFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return die("%s is not a cti-appscan tickets file: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	logf("appscan: %d application(s) in %s", len(tf.Tickets), safelog.Line(path))

	gateErr := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate)
	accounts := map[string]string{} // email -> accountId, "" when not found
	failed := 0
	for _, t := range tf.Tickets {
		r := appscanOne(ctx, c, cfg, t, forReal, gateErr, now, accounts, reportsDir)
		refs.Apps[t.Key] = r
		if r.Action == "error" {
			failed++
		}
	}
	if failed > 0 {
		logf("appscan: %d application ticket(s) could not be updated - see above", failed)
	}
	retireOrphans(ctx, c, cfg, tf, forReal, now)
	return exitOK
}

func appscanOne(ctx context.Context, c *jira.Client, cfg config.Config, t appscan.AppTicket,
	forReal bool, gateErr error, now time.Time, accounts map[string]string, reportsDir string) ticketref.Ref {

	name := safelog.Line(t.App)
	refFor := func(action string, is *jira.Issue, note string) ticketref.Ref {
		r := ticketref.Ref{Action: action, Note: note}
		if is != nil {
			r.Key, r.URL, r.Status = is.Key, c.BrowseURL(is.Key), is.Fields.Status.Name
		}
		return r
	}
	if t.Skip != "" {
		logf("appscan: %s: left alone - %s", name, safelog.Line(t.Skip))
		return refFor("skipped", nil, t.Skip)
	}
	label := appscan.AppLabel(t.Key)
	issues, err := c.Search(ctx, appscanJQL(cfg.JiraProjectKey, label), 5)
	if err != nil {
		logf("appscan: %s: searching for its ticket failed: %s", name, safelog.Line(err.Error()))
		return refFor("error", nil, "Jira could not be searched for its ticket")
	}
	var open *jira.Issue
	if len(issues) > 0 {
		open = &issues[0]
		if len(issues) > 1 {
			logf("appscan: %s: %d open tickets; updating the newest, %s", name, len(issues), open.Key)
		}
	}
	var prev appscanState
	if open != nil {
		if _, err := c.GetProperty(ctx, open.Key, appscanPropKey, &prev); err != nil {
			logf("appscan: %s: could not read what %s was last told (%s) - left alone",
				name, open.Key, safelog.Line(err.Error()))
			return refFor("error", open, "could not read what it was last told, so it was left alone")
		}
	}
	plan, why := planApp(open, prev, t)
	logf("appscan: %s: %s", name, why)

	switch plan {
	case appNothing:
		switch {
		case open == nil:
			return refFor("none", nil, "")
		case prev.Resolved:
			return refFor("resolved", open, "")
		}
		return refFor("unchanged", open, "")
	}

	if !forReal && gateErr != nil && (plan == appCreate || plan == appComment) {
		// Said in the preview too, so nothing downstream (cti-appreport
		// --only-ref) spends scanner calls on a ticket the real run will
		// not touch.
		logf("appscan: %s: WRITE GATE CLOSED - the real run would not file or comment", name)
		return refFor("gate-closed", open, "the Jira write gate is closed (JIRA_ALLOW_CREATE)")
	}
	// The scanner's own report, when cti-appreport fetched one. Optional:
	// without it the ticket carries every finding, and says nothing about
	// an attachment that is not there. Loaded before the preview, so a
	// preview shows exactly what a real run would attach.
	file := fmt.Sprintf("appscan-%s.txt", now.Format("2006-01-02"))
	full := []byte(appscanFullText(t, now))
	var prior *priorTicket
	if plan == appCreate && (!forReal || gateErr == nil) {
		// Not when a real run is about to stop at the closed write gate:
		// the lookup would be wasted calls.
		prior = findPrior(ctx, c, cfg, label, t, name)
	}
	rep, hasRep, repName := loadAppReport(t, plan == appCreate || plan == appComment, reportsDir, now, name)

	if !forReal {
		// The would-be text goes to stdout, which the runner writes to a
		// 0600 preview file rather than the journal: it names URLs and
		// parameters on our own applications.
		switch plan {
		case appCreate:
			fmt.Printf("===== would create for %s\n%s%s%s\n%s%s", oneLine(t.App, 80), appscanBody(t, now),
				priorNote(prior), reportNote(hasRep, repName), attachPreview(hasRep, repName, rep.Body, file, full),
				linkPreview(prior))
			return refFor("would-create", nil, "")
		case appComment:
			fmt.Printf("===== would comment on %s\n%s\n%s", open.Key, appscanComment(t, prev, now),
				attachPreview(hasRep, repName, rep.Body, file, full))
			return refFor("would-comment", open, "")
		}
		return refFor("would-resolve", open, "")
	}
	if gateErr != nil {
		logf("appscan: %s: WRITE GATE CLOSED - %s", name, safelog.Line(gateErr.Error()))
		return refFor("gate-closed", open, "the Jira write gate is closed (JIRA_ALLOW_CREATE)")
	}

	st := appscanState{Hash: t.Hash, Keys: stateKeys(t), PostedAt: now}
	attachReport := func(key string) {
		if !hasRep {
			return
		}
		if err := c.Attach(ctx, key, repName, rep.Body); err != nil {
			logf("appscan: %s: the scanner report did not attach to %s: %s", name, key, safelog.Line(err.Error()))
		}
	}

	switch plan {
	case appCreate:
		req := jira.IssueRequest{
			ProjectKey:  cfg.JiraProjectKey,
			IssueType:   cfg.JiraIssueType,
			Summary:     appscanSummary(t),
			Description: appscanBody(t, now) + priorNote(prior) + reportNote(hasRep, repName),
			Labels:      []string{"cti-agent", appscanLabel, label},
		}
		assignee, note := "", ""
		switch {
		case !t.OwnerListed:
			note = "no owner in app-owners.txt - unassigned"
		default:
			id, ok := accounts[t.Owner]
			if !ok {
				var err error
				id, err = c.AccountIDForEmail(ctx, t.Owner)
				if err != nil {
					logf("appscan: %s: owner %s not assignable: %s", name,
						safelog.Line(t.Owner), safelog.Line(err.Error()))
					id = ""
				}
				accounts[t.Owner] = id
			}
			if id == "" {
				note = "owner " + t.Owner + " was not found in Jira - unassigned"
			} else {
				req.AssigneeAccountID, assignee = id, t.Owner
			}
		}
		if t.Component != "" {
			req.Components = []string{t.Component}
		}
		res, err := c.CreateIssue(ctx, req)
		// Retry ONLY when Jira refused the request (400: nothing was
		// created). After a timeout or a 5xx the issue may exist, and a
		// retry would file a second one.
		if err != nil && jira.IsBadRequest(err) && (req.AssigneeAccountID != "" || len(req.Components) > 0) {
			// An assignee who cannot be assigned in this project, or a
			// component that does not exist, fails the whole create. The
			// findings matter more than the routing: file it plain, say so.
			logf("appscan: %s: create refused (%s) - retrying without assignee and component",
				name, safelog.Line(err.Error()))
			req.AssigneeAccountID, req.Components, assignee = "", nil, ""
			note = "Jira refused the assignee or component, so it was filed unassigned"
			res, err = c.CreateIssue(ctx, req)
		}
		if err != nil {
			logf("appscan: %s: creating its ticket failed: %s", name, safelog.Line(err.Error()))
			return refFor("error", nil, "Jira refused to create it")
		}
		if err := c.Attach(ctx, res.Key, file, full); err != nil {
			logf("appscan: %s: %s created but the full list did not attach: %s", name, res.Key, safelog.Line(err.Error()))
		}
		attachReport(res.Key)
		if err := c.SetProperty(ctx, res.Key, appscanPropKey, st); err != nil {
			logf("appscan: %s: could not record the findings on %s - next week will comment again: %s",
				name, res.Key, safelog.Line(err.Error()))
		}
		logf("appscan: %s: filed %s", name, res.Key)
		if prior != nil {
			if err := c.LinkIssues(ctx, jira.RelatesLink, res.Key, prior.Key); err != nil {
				logf("appscan: %s: %s says it follows %s, but the Jira link was refused: %s",
					name, res.Key, prior.Key, safelog.Line(err.Error()))
			} else {
				logf("appscan: %s: linked %s to the earlier %s", name, res.Key, prior.Key)
			}
		}
		addWatchers(ctx, c, res.Key, name, t.Watchers, accounts, logf)
		r := refFor("created", &jira.Issue{Key: res.Key}, note)
		r.Assignee = assignee
		return r

	case appComment:
		if err := c.AddComment(ctx, open.Key, appscanComment(t, prev, now)+reportNote(hasRep, repName)); err != nil {
			logf("appscan: %s: commenting on %s failed: %s", name, open.Key, safelog.Line(err.Error()))
			return refFor("error", open, "the comment with this week's findings was refused")
		}
		if err := c.Attach(ctx, open.Key, file, full); err != nil {
			logf("appscan: %s: comment posted but the full list did not attach: %s", name, safelog.Line(err.Error()))
		}
		attachReport(open.Key)
		if err := c.SetProperty(ctx, open.Key, appscanPropKey, st); err != nil {
			logf("appscan: %s: could not record the findings on %s: %s", name, open.Key, safelog.Line(err.Error()))
		}
		addWatchers(ctx, c, open.Key, name, t.Watchers, accounts, logf)
		return refFor("commented", open, "")

	case appDone:
		text := fmt.Sprintf("The weekly application-security check on %s found nothing of Serious "+
			"severity or above still open on %s (last scan %s, %s). This ticket can be closed "+
			"once that is confirmed in Qualys.", now.Format("2 January 2006"), wikiEscape(t.App),
			t.Scanned.Format("2006-01-02"), wikiEscape(t.ScanLabel))
		if err := c.AddComment(ctx, open.Key, text); err != nil {
			logf("appscan: %s: commenting on %s failed: %s", name, open.Key, safelog.Line(err.Error()))
			return refFor("error", open, "the closing comment was refused")
		}
		st.Resolved = true
		// Keep what it was last told: if the same findings come back, they
		// are reported as back, not all as new.
		st.Keys, st.Hash = prev.Keys, prev.Hash
		if err := c.SetProperty(ctx, open.Key, appscanPropKey, st); err != nil {
			logf("appscan: %s: could not record the state on %s: %s", name, open.Key, safelog.Line(err.Error()))
		}
		return refFor("resolved", open, "")
	}
	return refFor("none", nil, "")
}

// loadAppReport reads an application's zipped scanner report from the
// cti-appreport directory, when one was fetched and it is wanted.
func loadAppReport(t appscan.AppTicket, wanted bool, reportsDir string, now time.Time, name string) (appscan.Report, bool, string) {
	rep, hasRep := appscan.Report{}, false
	if wanted {
		var err error
		rep, hasRep, err = appscan.LoadReport(reportsDir, t.Key, t.AppID)
		if err != nil {
			logf("appscan: %s: scanner report not attached: %s", name, safelog.Line(err.Error()))
		}
	}
	return rep, hasRep, fmt.Sprintf("%s-report-%s.zip", rep.Provider, now.Format("2006-01-02"))
}

// linkPreview says which closed ticket a real run would link to.
func linkPreview(p *priorTicket) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("----- would link to %s (%s), the application's earlier closed ticket\n",
		oneLine(p.Key, 40), oneLine(p.Status, 40))
}

// attachPreview says what a real run would attach, by name and size.
func attachPreview(hasRep bool, repName string, repBody []byte, file string, full []byte) string {
	out := fmt.Sprintf("----- would attach %s (%s)\n", file, kb(len(full)))
	if hasRep {
		out += fmt.Sprintf("----- would attach %s (%s)\n", repName, kb(len(repBody)))
	} else {
		out += "----- no scanner report to attach (none fetched for this application)\n"
	}
	return out
}

func kb(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d bytes", n)
	}
	return fmt.Sprintf("%d KB", (n+1023)/1024)
}

// reportNote is the line that tells the reader the scanner's report is
// attached, and what it is - including that it carries the scan account's
// session cookies, which is why it stays inside the project.
func reportNote(has bool, file string) string {
	if !has {
		return ""
	}
	return "\n\n*Attached:* " + wikiEscape(file) + " - the scanner's own report for this application " +
		"(zipped HTML: open vulnerabilities, with the request and response the scanner used for each; " +
		"potential findings are marked *Potential* there too). It includes session cookies from the " +
		"scan account - do not forward it outside this project."
}

// addWatchers adds each email in app-owners.txt's watchers= as a watcher.
// Best effort: a watcher who cannot be found or added is logged and skipped -
// it must never cost the ticket. Adding an existing watcher is harmless, so
// this runs on create and on every comment, which also picks up watchers
// added to the file later. Account lookups are shared with the assignee's.
func addWatchers(ctx context.Context, c *jira.Client, key, app string, emails []string,
	accounts map[string]string, logf func(string, ...any)) {
	if len(emails) > appscan.MaxWatchers { // the parser caps it; the file is also input here
		emails = emails[:appscan.MaxWatchers]
	}
	for _, e := range emails {
		id, ok := accounts[e]
		if !ok {
			var err error
			id, err = c.AccountIDForEmail(ctx, e)
			if err != nil {
				logf("appscan: %s: watcher %s not found in Jira, skipped: %s", app,
					safelog.Line(e), safelog.Line(err.Error()))
				id = ""
			}
			accounts[e] = id
		}
		if id == "" {
			continue
		}
		if err := c.AddWatcher(ctx, key, id); err != nil {
			logf("appscan: %s: adding watcher %s to %s failed: %s", app, safelog.Line(e), key, safelog.Line(err.Error()))
		}
	}
}

func appscanSummary(t appscan.AppTicket) string {
	confirmed, potential := appscan.Split(t.Findings)
	if len(confirmed) == 0 {
		return fmt.Sprintf("AppSec: %s - %d POTENTIAL finding(s) to verify (worst %s, unconfirmed)",
			oneLine(t.App, 80), len(potential), appscan.SeverityName(appscan.AppTicket{Findings: potential}.Worst()))
	}
	s := fmt.Sprintf("AppSec: %s - %d finding(s) to fix", oneLine(t.App, 80), len(confirmed))
	if len(potential) > 0 {
		s += fmt.Sprintf(", %d potential to verify", len(potential))
	}
	return s + fmt.Sprintf(" (worst %s)", appscan.SeverityName(appscan.AppTicket{Findings: confirmed}.Worst()))
}

// potentialPanel is the callout above the potential findings. Explicit on
// purpose: an unconfirmed finding left to speak for itself gets answered
// with "the scanner didn't confirm it, so it isn't there".
const potentialPanel = "{panel:title=POTENTIAL findings - unconfirmed by the scanner, listed here on purpose}\n" +
	"Qualys reports the findings below as *potential*: it saw behaviour that matches the " +
	"vulnerability but could not prove it with a working exploit. They are on this ticket " +
	"*deliberately*, because they are rated Critical or Urgent - too severe to leave unread. " +
	"\"Not confirmed\" does *not* mean \"not there\": they are in the scan results, and they are " +
	"marked *Potential* in Qualys and in the attached Qualys report.\n\n" +
	"*Please look at each one:* fix it if it is real, or comment on this ticket that it is a false " +
	"positive and why, so AppSec can mark it in Qualys and it stops coming back.\n" +
	"{panel}\n"

func oneLine(s string, max int) string {
	return clip(strings.Join(strings.Fields(s), " "), max)
}

// clip cuts to max runes, never inside a UTF-8 sequence.
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

// capText is the last line of defence for Jira's length limit.
func capText(s string) string {
	if len(s) <= hardMax {
		return s
	}
	cut := s[:hardMax]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "\n\n_[cut here to fit Jira - the attached file has everything]_"
}

// appscanBody is the ticket description, Jira wiki markup.
func appscanBody(t appscan.AppTicket, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Filed automatically by the CTI agent's weekly application-security check "+
		"for *%s*. Each finding below says where it is, what the scanner saw, the risk, and how "+
		"to fix it (from the Qualys KnowledgeBase). The list is refreshed every week; this "+
		"ticket gets a comment only when it changes, and the attached file always has the full "+
		"current list.\n\n", wikiEscape(t.App))
	b.WriteString(appscanHeader(t))
	writeAll(&b, t.Findings, maxBody-b.Len())
	fmt.Fprintf(&b, "\n_Generated %s; findings %s._", now.UTC().Format("2006-01-02 15:04 UTC"), t.Hash)
	return capText(b.String())
}

func appscanHeader(t appscan.AppTicket) string {
	var b strings.Builder
	owner := "not listed in app-owners.txt"
	if t.OwnerListed {
		owner = t.Owner
	}
	fmt.Fprintf(&b, "*Owner:* %s\n", wikiEscape(owner))
	if t.Target != "" {
		fmt.Fprintf(&b, "*Target:* {{%s}}\n", wikiEscape(clip(t.Target, maxField)))
	}
	if len(t.Covers) > 0 {
		fmt.Fprintf(&b, "*Stands in for:* {{%s}} - this is a staging/test copy scanned instead of production. "+
			"Fix it in the code, plugins or configuration here, then deploy: production itself is not "+
			"scanned, so check that anything configured only on production (edge, WAF, TLS, headers) "+
			"matches.\n", wikiEscape(strings.Join(t.Covers, ", ")))
	}
	fmt.Fprintf(&b, "*Last scan:* %s (%s)\n", t.Scanned.UTC().Format("2006-01-02"), wikiEscape(t.ScanLabel))
	if strings.HasPrefix(t.PortalURL, "https://") {
		fmt.Fprintf(&b, "*In Qualys:* [open the application|%s]\n", wikiURL(t.PortalURL))
	}
	confirmed, potential := appscan.Split(t.Findings)
	counts := map[appscan.Severity]int{}
	for _, f := range confirmed {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []appscan.Severity{5, 4, 3} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], appscan.SeverityName(s)))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "*To fix:* %s", strings.Join(parts, ", "))
	} else {
		b.WriteString("*To fix:* nothing of Serious or above")
	}
	if t.Lower > 0 {
		fmt.Fprintf(&b, " (plus %d Medium/Minimal, not listed)", t.Lower)
	}
	if len(potential) > 0 {
		pc := map[appscan.Severity]int{}
		for _, f := range potential {
			pc[f.Severity]++
		}
		var pp []string
		for _, s := range []appscan.Severity{5, 4} {
			if pc[s] > 0 {
				pp = append(pp, fmt.Sprintf("%d %s", pc[s], appscan.SeverityName(s)))
			}
		}
		fmt.Fprintf(&b, "\n*To verify:* %s *POTENTIAL* (unconfirmed by the scanner) - listed in their own "+
			"section below, not left out", strings.Join(pp, ", "))
	}
	b.WriteString("\n_Severity is Qualys WAS's own 1-5 scale, about one HTTP response - not the fleet's Sev1-Sev5._\n\n")
	return b.String()
}

// writeAll writes the confirmed findings, then the potential ones under
// their callout. Potentials are never folded in among the confirmed: the
// panel is what stops them being read as either certain or absent.
func writeAll(b *strings.Builder, fs []appscan.TicketFinding, budget int) {
	confirmed, potential := appscan.Split(fs)
	start := b.Len()
	reserve := 0
	if len(potential) > 0 {
		// Room for the callout and at least a line per potential: a long
		// confirmed list must not push the panel out of the text.
		reserve = len(potentialHead) + len(potentialPanel) + 2000
	}
	writeFindings(b, confirmed, budget-reserve)
	if len(potential) > 0 {
		b.WriteString(potentialHead + potentialPanel)
		writeFindings(b, potential, budget-(b.Len()-start))
	}
}

const potentialHead = "h2. POTENTIAL - please verify\n"

// writeFindings writes full detail while it fits in budget, then one line
// per remaining finding pointing at the attachment - those lines budgeted
// too, so a long tail cannot push the text past Jira's limit.
func writeFindings(b *strings.Builder, fs []appscan.TicketFinding, budget int) {
	for i, f := range fs {
		block := findingBlock(f)
		if len(block) > budget {
			head := fmt.Sprintf("h3. %d more finding(s) - full detail in the attached file\n", len(fs)-i)
			b.WriteString(head)
			budget -= len(head)
			for j, g := range fs[i:] {
				line := fmt.Sprintf("* \\[%s\\] %s (QID %s), %d place(s)\n", sevLabel(g),
					wikiEscape(oneLine(g.Title, 120)), wikiEscape(g.ID), len(g.Instances))
				if len(line) > budget-200 {
					fmt.Fprintf(b, "* ...and %d more - see the attached file\n", len(fs)-i-j)
					return
				}
				b.WriteString(line)
				budget -= len(line)
			}
			return
		}
		b.WriteString(block)
		budget -= len(block)
	}
}

// sevLabel is the bracketed severity; a potential finding says so in the
// label itself, so the word travels with any line quoted on its own.
func sevLabel(f appscan.TicketFinding) string {
	if f.Potential {
		return "POTENTIAL " + appscan.SeverityName(f.Severity) + " - unconfirmed, please verify"
	}
	return appscan.SeverityName(f.Severity)
}

func findingBlock(f appscan.TicketFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "h3. \\[%s\\] %s (QID %s) - %s\n", sevLabel(f),
		wikiEscape(oneLine(f.Title, 200)), wikiEscape(f.ID), wikiEscape(strings.ToLower(f.Status)))
	if !f.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "First seen %s.\n", f.FirstSeen.UTC().Format("2006-01-02"))
	}
	fmt.Fprintf(&b, "*Where* (%d):\n", len(f.Instances))
	for i, in := range f.Instances {
		if i >= 25 {
			fmt.Fprintf(&b, "* ...and %d more in the attached file\n", len(f.Instances)-i)
			break
		}
		line := "* {{" + wikiEscape(clip(appscan.RedactURL(in.URL), maxField)) + "}}"
		if in.Param != "" {
			line += " parameter {{" + wikiEscape(clip(in.Param, maxField)) + "}}"
		}
		b.WriteString(line + "\n")
	}
	// One detection in full, the first that has evidence - enough to
	// reproduce it. Every place's evidence is in the attached file.
	for _, in := range f.Instances {
		if in.Evidence != nil {
			b.WriteString(evidenceWiki(in))
			break
		}
	}
	if r := f.Remedy; r != nil {
		para := func(title, text string) {
			if strings.TrimSpace(text) != "" {
				fmt.Fprintf(&b, "*%s*\n%s\n", title, wikiText(text))
			}
		}
		para("Risk", r.Consequence)
		para("What the scanner found", r.Diagnosis)
		para("How to fix it", r.Solution)
		if len(r.CVEs) > 0 {
			fmt.Fprintf(&b, "*CVEs:* %s\n", wikiEscape(strings.Join(r.CVEs, ", ")))
		}
	} else {
		b.WriteString("_The Qualys KnowledgeBase returned no remediation text for this QID this week - see the finding in Qualys._\n")
	}
	b.WriteString("\n")
	return b.String()
}

var noformatRE = regexp.MustCompile(`(?i)\{noformat`)

// evidenceWiki is how the scanner found one instance, in wiki markup. The
// proof goes in a {noformat} block, where nothing is rendered - the one place
// a response excerpt full of HTML cannot become markup - with any
// "{noformat" in it defused so it cannot end the block early.
func evidenceWiki(in appscan.Instance) string {
	e := in.Evidence
	var b strings.Builder
	b.WriteString("*How the scanner found it*")
	if e.Authenticated {
		b.WriteString(" (logged in)")
	}
	b.WriteString(":\n")
	if e.Link != "" {
		req := e.Link
		if e.Method != "" {
			req = e.Method + " " + req
		}
		fmt.Fprintf(&b, "* Request: {{%s}}\n", wikiEscape(clip(req, maxField)))
	}
	if e.Payload != "" {
		fmt.Fprintf(&b, "* Payload: {{%s}}\n", wikiEscape(clip(e.Payload, maxField)))
	}
	if len(e.AccessPath) > 0 {
		var hops []string
		for _, u := range e.AccessPath {
			hops = append(hops, "{{"+wikiEscape(clip(u, maxField))+"}}")
		}
		fmt.Fprintf(&b, "* Reached from: %s\n", strings.Join(hops, " > "))
	}
	if p := strings.TrimSpace(e.Proof); p != "" {
		b.WriteString("* What came back:\n{noformat}\n" + noformatRE.ReplaceAllString(p, "(noformat") + "\n{noformat}\n")
	}
	return b.String()
}

// maxEvidencePerFinding caps evidence in the attachment per finding.
const maxEvidencePerFinding = 10

// evidenceText is the same for the plain-text attachment.
func evidenceText(e *appscan.Evidence) string {
	var b strings.Builder
	if e.Link != "" {
		fmt.Fprintf(&b, "      request: %s %s\n", e.Method, e.Link)
	}
	if e.Payload != "" {
		fmt.Fprintf(&b, "      payload: %s\n", e.Payload)
	}
	if len(e.AccessPath) > 0 {
		fmt.Fprintf(&b, "      reached from: %s\n", strings.Join(e.AccessPath, " > "))
	}
	if e.Authenticated {
		b.WriteString("      scanned logged in\n")
	}
	if p := strings.TrimSpace(e.Proof); p != "" {
		fmt.Fprintf(&b, "      what came back:\n        %s\n", strings.ReplaceAll(p, "\n", "\n        "))
	}
	return b.String()
}

// appscanComment is the weekly update when the findings changed.
func appscanComment(t appscan.AppTicket, prev appscanState, now time.Time) string {
	before := map[string]bool{}
	for _, k := range prev.Keys {
		before[k] = true
	}
	now2 := map[string]bool{}
	for _, k := range t.InstanceKeys() {
		now2[stateKey(k)] = true
	}
	// Gone, counted per QID: the ticket keeps a hash of each place, not the
	// URL, so the place itself is in last week's attachment.
	goneByQID := map[string]int{}
	gone := 0
	for k := range before {
		if !now2[k] {
			gone++
			goneByQID[strings.SplitN(k, ":", 2)[0]]++
		}
	}
	// Findings with at least one new instance, shown in full.
	var fresh []appscan.TicketFinding
	newCount := 0
	for _, f := range t.Findings {
		isNew := false
		for _, in := range f.Instances {
			if !before[stateKey(f.InstanceKey(in))] {
				isNew = true
				newCount++
			}
		}
		if isNew {
			fresh = append(fresh, f)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "This week's scan (%s, %s) changed the findings: %d new place(s), %d no longer "+
		"detected, %d finding(s) open in total. The attached file has the full current list.\n\n",
		t.Scanned.UTC().Format("2006-01-02"), wikiEscape(t.ScanLabel), newCount, gone, len(t.Findings))
	if len(fresh) > 0 {
		b.WriteString("h3. New or newly seen\n")
		writeAll(&b, fresh, maxBody-b.Len()-3000)
	}
	if gone > 0 {
		b.WriteString("h3. No longer detected\n")
		qids := make([]string, 0, len(goneByQID))
		for q := range goneByQID {
			qids = append(qids, q)
		}
		sort.Strings(qids)
		for i, q := range qids {
			if i >= 50 || b.Len() > maxBody {
				fmt.Fprintf(&b, "* ...and %d more QID(s)\n", len(qids)-i)
				break
			}
			fmt.Fprintf(&b, "* QID %s: %d place(s)\n", wikiEscape(q), goneByQID[q])
		}
	}
	fmt.Fprintf(&b, "\n_Generated %s; findings %s._", now.UTC().Format("2006-01-02 15:04 UTC"), t.Hash)
	return capText(b.String())
}

// appscanFullText is the attachment: every finding, every place, plain text.
func appscanFullText(t appscan.AppTicket, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s - application security findings, Serious and above "+
		"(plus POTENTIAL Critical/Urgent, marked)\nGenerated %s\n",
		t.App, now.UTC().Format("2006-01-02 15:04 UTC"))
	if t.Target != "" {
		fmt.Fprintf(&b, "Target: %s\n", t.Target)
	}
	fmt.Fprintf(&b, "Last scan: %s (%s)\n\n", t.Scanned.UTC().Format("2006-01-02"), t.ScanLabel)
	for _, f := range t.Findings {
		fmt.Fprintf(&b, "== [%s] %s (QID %s) - %s\n", sevLabel(f), f.Title, f.ID,
			strings.ToLower(f.Status))
		shown := 0
		for _, in := range f.Instances {
			if in.Param != "" {
				fmt.Fprintf(&b, "  - %s  (parameter %s)\n", appscan.RedactURL(in.URL), in.Param)
			} else {
				fmt.Fprintf(&b, "  - %s\n", appscan.RedactURL(in.URL))
			}
			// Evidence for the first few places per finding: the rest are
			// the same flaw, and an application with a thousand places must
			// not produce an attachment Jira refuses.
			if in.Evidence != nil && shown < maxEvidencePerFinding {
				b.WriteString(evidenceText(in.Evidence))
				shown++
			}
		}
		if r := f.Remedy; r != nil {
			for _, p := range [][2]string{{"Risk", r.Consequence}, {"What the scanner found", r.Diagnosis},
				{"How to fix it", r.Solution}} {
				if strings.TrimSpace(p[1]) != "" {
					fmt.Fprintf(&b, "\n  %s:\n  %s\n", p[0], strings.ReplaceAll(p[1], "\n", "\n  "))
				}
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// wikiText escapes free text for the wiki renderer while keeping its lines:
// "- item" becomes a bullet, and markup characters are backslash-escaped so a
// KnowledgeBase sentence cannot turn into bold, a link or a table.
func wikiText(s string) string {
	r := wikiMarkup
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		bullet := strings.HasPrefix(l, "- ")
		if bullet {
			l = strings.TrimPrefix(l, "- ")
		}
		l = r.Replace(l)
		if strings.HasPrefix(l, "-") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "bq.") ||
			(len(l) > 2 && l[0] == 'h' && l[1] >= '1' && l[1] <= '6' && l[2] == '.') {
			l = "\\" + l
		}
		if bullet {
			l = "* " + l
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// wikiMarkup escapes every character the wiki renderer gives meaning to.
// Backslash FIRST, or the escapes it adds would be escaped again; "!" because
// !https://x/y.png! embeds an external image in the ticket.
var wikiMarkup = strings.NewReplacer("\\", "\\\\", "{", "\\{", "}", "\\}", "[", "\\[", "]", "\\]",
	"|", "\\|", "*", "\\*", "_", "\\_", "^", "\\^", "~", "\\~", "+", "\\+", "!", "\\!",
	"?", "\\?")

// wikiURL keeps a URL usable inside [text|url]: the pipe and brackets would
// end the link early.
func wikiURL(u string) string {
	return strings.NewReplacer("|", "%7C", "[", "%5B", "]", "%5D", " ", "%20").Replace(u)
}
