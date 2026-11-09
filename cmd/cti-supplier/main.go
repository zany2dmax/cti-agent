// cti-supplier is the supplier-request lane's deterministic half: it finds the
// new supplier requests in the shared mailbox, reads their forms, and later
// turns the model's judgements into Kanban items and one digest email.
//
//	cti-supplier --dry-run|--for-real --collect DIR      find new requests, write DIR/requests.json and DIR/NNN.input.txt
//	  (the runner shows each NNN.input.txt to the no-tools model and saves NNN.result.json)
//	cti-supplier --dry-run|--for-real --finish DIR       judge, write DIR/digest.*; --for-real also files the Kanban items
//	cti-supplier --for-real --commit-seen DIR/seen.json  after the send: do not report these requests again
//
// Like every command that changes something, it must be told how to run:
// --dry-run reads the mailbox and writes only its own work directory;
// --for-real files the Kanban items and records what was reported.
//
// It sends nothing: run-supplier hands the digest to cti-mailer. It changes
// nothing in the mailbox, never replies to a requester, and never opens the
// tax or bank attachments (internal/supplier is the only path to attachment
// bytes, and it refuses them by type and by name).
//
// With no model judgement for a request - the model was not set, was down, or
// gave output code cannot use - the request is Unsure, which gets the same
// Kanban to-do as a Yes. The lane degrades toward asking a person.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/cli"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/emailkit"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/mailbox"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/supplier"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() { os.Exit(run()) }

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "[supplier] "+format+"\n", a...) }

func die(format string, a ...any) int {
	logf("error  : "+format, a...)
	return exitErr
}

func run() int {
	collectDir := flag.String("collect", "", "find new supplier requests and write what the model needs into this directory")
	finishDir := flag.String("finish", "", "judge the requests in this directory, file the Kanban items and write the digest")
	dryRun := flag.Bool("dry-run", false, "read and judge, say what would be filed, and write nothing to Jira or the record of what was reported")
	forReal := flag.Bool("for-real", false, "with --finish: file the Kanban items; with --commit-seen: record the requests as reported")
	commitSeen := flag.String("commit-seen", "", "record a seen.json from --finish, so the same requests are not reported again; then exit")
	window := flag.Duration("since", 0, "how far back to look for requests (default SUPPLIER_WINDOW_DAYS days, else 3)")
	flag.Parse()

	mode, msg := cli.Resolve("cti-supplier", *dryRun, *forReal, false, false, cli.Words{
		DryRun:  "read the mailbox and judge, file nothing in Jira and record nothing as reported",
		ForReal: "file the Kanban items (--finish) or record requests as reported (--commit-seen)",
	})
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		return 2
	}
	n := 0
	for _, s := range []string{*collectDir, *finishDir, *commitSeen} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return die("give exactly one of --collect DIR, --finish DIR, --commit-seen FILE")
	}

	fleetenv.Load()
	switch {
	case *commitSeen != "":
		if !mode.ForReal {
			logf("dry run - nothing recorded as reported")
			return exitOK
		}
		return doCommitSeen(*commitSeen)
	case *collectDir != "":
		return doCollect(*collectDir, *window)
	default:
		return doFinish(*finishDir, mode.ForReal)
	}
}

// ── settings ────────────────────────────────────────────────────────────────

func env(k string) string { return strings.TrimSpace(os.Getenv(k)) }

func laneConfig() supplier.Config {
	c := supplier.Config{
		Question:   env("SUPPLIER_QUESTION"),
		Critical:   env("SUPPLIER_MEANING"),
		TPRM:       env("SUPPLIER_TPRM"),
		UnsureText: env("SUPPLIER_UNSURE_TEXT"),
	}
	// Staff mail domains, for the "not a supplier request" answer: the domain of
	// the request address itself plus any listed in SUPPLIER_INTERNAL_DOMAINS.
	if a := env("SUPPLIER_ADDRESS"); strings.Contains(a, "@") {
		c.InternalDomains = append(c.InternalDomains, a[strings.LastIndex(a, "@")+1:])
	}
	for _, d := range strings.Split(env("SUPPLIER_INTERNAL_DOMAINS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			c.InternalDomains = append(c.InternalDomains, d)
		}
	}
	// Set and empty means "no technology words"; unset means the defaults.
	if v, ok := os.LookupEnv("SUPPLIER_TECH_TERMS"); ok {
		c.TechTerms = []string{}
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				c.TechTerms = append(c.TechTerms, t)
			}
		}
	}
	return c
}

func policy() supplier.Policy {
	var p supplier.Policy
	for _, e := range strings.Split(env("SUPPLIER_FORM_TYPES"), ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			p.Exts = append(p.Exts, e)
		}
	}
	return p
}

func statePath() string {
	if p := env("SUPPLIER_SEEN_FILE"); p != "" {
		return p
	}
	home := env("FLEET_HOME")
	if home == "" {
		return ""
	}
	return filepath.Join(home, "state", "supplier-seen.json")
}

// ── collect ─────────────────────────────────────────────────────────────────

type graphMail struct {
	c               *graph.Client
	mailbox, folder string
	address         string
}

func (g graphMail) Addressed(ctx context.Context, since time.Time) ([]graph.AddressedMessage, error) {
	return g.c.MessagesAddressedTo(ctx, g.mailbox, g.folder, g.address, since)
}

func doCollect(dir string, window time.Duration) int {
	address := env("SUPPLIER_ADDRESS")
	if address == "" {
		// An unset address means the lane does nothing, like every other lane.
		logf("SUPPLIER_ADDRESS is not set, so the lane does nothing")
		if err := writeItems(dir, nil, 0); err != nil {
			return die("%s", safelog.Line(err.Error()))
		}
		return exitOK
	}
	cfg, err := config.LoadGraphOnly()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	if window <= 0 {
		days := 3
		if v := env("SUPPLIER_WINDOW_DAYS"); v != "" {
			d, err := strconv.Atoi(v)
			if err != nil || d < 1 || d > 60 {
				return die("SUPPLIER_WINDOW_DAYS %q is not a number of days from 1 to 60", safelog.Line(v))
			}
			days = d
		}
		window = time.Duration(days) * 24 * time.Hour
	}
	folder := env("SUPPLIER_FOLDER")
	if folder == "" {
		folder = cfg.GraphFolder
	}
	seen, err := supplier.LoadSeen(statePath())
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	g := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	mail := graphMail{c: g, mailbox: cfg.GraphMailbox, folder: folder, address: address}
	src := supplier.GraphSource{Client: g, Mailbox: cfg.GraphMailbox}

	// The mail filter's quarantine digest also lands on the list. It comes from
	// the one address the cleanup lane already knows (MAILBOX_DIGEST_SENDERS),
	// matched exactly with the subject, so a person's reply to a digest is not
	// mistaken for one. Unset: nothing is skipped.
	digestSenders := splitList(cfg.MailboxDigestSenders)
	automatic := func(from, subject string) bool { return mailbox.QuarantineDigest(from, subject, digestSenders) }
	items, skipped, err := supplier.Collect(ctx, mail, src, policy(), laneConfig(), seen, cfg.GraphMailbox, time.Now().Add(-window), automatic)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	for _, it := range items {
		r := it.Request
		again := ""
		if it.Update {
			again = ", reported before: new message"
		}
		logf("found  : %s (form %s, %d file(s) left unopened%s)", safelog.Line(r.Name()), r.State, len(r.Skipped), again)
	}
	logf("collect: %d new request(s) in the last %s, %d already reported, %d automatic message(s) left out", len(items), window, len(seen), skipped)
	if err := writeItems(dir, items, skipped); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	return exitOK
}

func itemsPath(dir string) string { return filepath.Join(dir, "requests.json") }
func inputPath(dir string, i int) string {
	return filepath.Join(dir, fmt.Sprintf("%03d.input.txt", i))
}
func resultPath(dir string, i int) string {
	return filepath.Join(dir, fmt.Sprintf("%03d.result.json", i))
}

// collected is requests.json: the new requests and how many automatic messages
// were left out, which the digest says.
type collected struct {
	Items            []supplier.Item `json:"items"`
	AutomaticSkipped int             `json:"automatic_skipped"`
}

func writeItems(dir string, items []supplier.Item, automatic int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(collected{Items: items, AutomaticSkipped: automatic}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(itemsPath(dir), b, 0o600); err != nil {
		return err
	}
	for i, it := range items {
		if err := os.WriteFile(inputPath(dir, i), []byte(it.Input), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// ── finish ──────────────────────────────────────────────────────────────────

func doFinish(dir string, fileJira bool) int {
	b, err := os.ReadFile(itemsPath(dir)) // #nosec G304 -- the runner's own work directory
	if err != nil {
		return die("reading %s: %s", safelog.Line(itemsPath(dir)), safelog.Line(err.Error()))
	}
	var col collected
	if err := json.Unmarshal(b, &col); err != nil {
		return die("%s does not parse: %s", safelog.Line(itemsPath(dir)), safelog.Line(err.Error()))
	}
	items := col.Items
	if len(items) == 0 {
		logf("finish : no new requests, nothing to judge or send")
		return exitOK
	}

	results := map[int][]byte{}
	for i := range items {
		// #nosec G304 -- a file the runner wrote in its own work directory.
		if rb, err := os.ReadFile(resultPath(dir, i)); err == nil {
			results[i] = rb
		}
	}
	logf("finish : %d request(s), %d with a model judgement", len(items), len(results))

	cfg := laneConfig()
	project := env("SUPPLIER_JIRA_PROJECT")
	var tickets supplier.Tickets
	if project != "" {
		tickets = newTickets(project, fileJira)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	outcomes := supplier.Finish(ctx, items, results, cfg, tickets, project, fileJira)

	var problems []string
	for _, o := range outcomes {
		r := o.Request
		logf("%-8s: %s - %s (item: %s %s)", strings.ToLower(supplier.VerdictLabel(r.Decision.Verdict)),
			safelog.Line(r.Name()), safelog.Line(r.Decision.Reason), o.Ticket, r.TicketKey)
		if o.Err != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", safelog.Line(r.Name()), safelog.Line(o.Err)))
		}
	}

	block, ok := supplier.Digest(supplier.Requests(outcomes), emailkit.Org(), time.Now(),
		env("SUPPLIER_BOARD_URL"), env("SUPPLIER_BOARD_NAME"), col.AutomaticSkipped)
	if ok {
		for name, body := range map[string]string{"digest.html": block.HTML, "digest.txt": block.Text, "digest.subject": block.Subject + "\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				return die("%s", safelog.Line(err.Error()))
			}
		}
	}
	// Only what did not fail is recorded as reported: a request whose item could
	// not be filed is collected again next run and filed then.
	sb, _ := json.Marshal(supplier.SeenRecords(outcomes))
	if err := os.WriteFile(filepath.Join(dir, "seen.json"), sb, 0o600); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	pb := strings.Join(problems, "\n")
	if pb != "" {
		pb += "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "problems.txt"), []byte(pb), 0o600); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	return exitOK
}

func doCommitSeen(path string) int {
	dest := statePath()
	if dest == "" {
		return die("FLEET_HOME is not set, so there is no state directory to record in")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the runner's own seen.json
	if err != nil {
		return die("reading %s: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	var records []supplier.SeenRecord
	if err := json.Unmarshal(b, &records); err != nil {
		return die("%s does not parse: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	seen, err := supplier.LoadSeen(dest)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	now := time.Now()
	for _, r := range records {
		seen.RecordEntry(r.Label, r.Entry, now)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	if err := seen.Save(dest); err != nil {
		return die("saving %s: %s", safelog.Line(dest), safelog.Line(err.Error()))
	}
	logf("seen   : %d request(s) recorded as reported", len(records))
	return exitOK
}

// ── Jira ────────────────────────────────────────────────────────────────────

// closedTickets is the lane's Jira when it may not write: every call says why.
type closedTickets struct{ why string }

func (c closedTickets) Find(context.Context, string) (string, string, bool, error) {
	return "", "", false, errors.New(c.why)
}
func (c closedTickets) Create(context.Context, string, string, []string) (string, string, error) {
	return "", "", errors.New(c.why)
}
func (c closedTickets) Comment(context.Context, string, string) error { return errors.New(c.why) }

type jiraTickets struct {
	c         *jira.Client
	project   string
	issueType string
	assignee  string
}

func (j jiraTickets) Find(ctx context.Context, jql string) (string, string, bool, error) {
	issues, err := j.c.Search(ctx, jql, 1)
	if err != nil {
		return "", "", false, err
	}
	if len(issues) == 0 {
		return "", "", false, nil
	}
	return issues[0].Key, j.c.BrowseURL(issues[0].Key), true, nil
}

// Comment adds a comment to an item. The lane has no call that closes, reopens
// or edits one: that stays with a person.
func (j jiraTickets) Comment(ctx context.Context, key, text string) error {
	return j.c.AddComment(ctx, key, text)
}

func (j jiraTickets) Create(ctx context.Context, summary, description string, labels []string) (string, string, error) {
	res, err := j.c.CreateIssue(ctx, jira.IssueRequest{
		ProjectKey: j.project, IssueType: j.issueType, Summary: summary, Description: description,
		Labels: append([]string{"cti-agent"}, labels...), AssigneeAccountID: j.assignee,
	})
	var cont *jira.ContinuationError
	if errors.As(err, &cont) {
		logf("warn   : %s", safelog.Line(err.Error())) // the item exists
		err = nil
	}
	if err != nil {
		return "", "", err
	}
	return res.Key, j.c.BrowseURL(res.Key), nil
}

// newTickets builds the lane's Jira. A dry run gets a client that is never
// called (Finish does not touch Jira unless filing), so no credentials are
// needed to preview; a real run needs them, and the write gate.
func newTickets(project string, fileJira bool) supplier.Tickets {
	if !fileJira {
		return closedTickets{why: "dry run"}
	}
	if err := jira.CheckAllowed(project, env("JIRA_ALLOW_CREATE")); err != nil {
		logf("WRITE GATE CLOSED - no Kanban items filed: %s", safelog.Line(err.Error()))
		return closedTickets{why: "the Jira write gate is closed (JIRA_ALLOW_CREATE)"}
	}
	var missing []string
	for _, k := range []string{"JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN"} {
		if env(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return closedTickets{why: "missing " + strings.Join(missing, ", ")}
	}
	c := jira.New(env("JIRA_BASE_URL"), env("JIRA_EMAIL"), env("JIRA_API_TOKEN"))
	if id := env("JIRA_CLOUD_ID"); id != "" {
		gw, err := jira.CloudGateway(id)
		if err != nil {
			return closedTickets{why: err.Error()}
		}
		c.APIBase = gw
	}
	t := jiraTickets{c: c, project: project, issueType: env("SUPPLIER_JIRA_TYPE")}
	if t.issueType == "" {
		t.issueType = "Task"
	}
	if email := env("SUPPLIER_OWNER_EMAIL"); email != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		id, err := c.AccountIDForEmail(ctx, email)
		if err != nil {
			// Never a guess: an unknown owner leaves the items unassigned.
			logf("warn   : %s is not a Jira user the lane can find, so items are unassigned: %s",
				safelog.Line(email), safelog.Line(err.Error()))
		} else {
			t.assignee = id
		}
	}
	return t
}

// splitList parses a comma-separated fleet.env list, dropping empties.
func splitList(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}
