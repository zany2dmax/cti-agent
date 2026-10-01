// cti-jira files and tracks remediation tickets for confirmed exposure.
//
//	cti-jira --check                      # read-only: auth, project, required fields
//	cti-jira --test-ticket                # dry run: print the ticket, create nothing
//	cti-jira --test-ticket --for-real     # actually create ONE labelled test ticket
//
// # WHY --for-real AND NOT --dry-run
//
// The default is the safe direction, which means the flag has to be the
// dangerous one. cti-mailbox learned this the same way: a --dry-run flag means
// forgetting it sends, and the cost of forgetting here is a ticket in a
// project IT watches. So nothing is created unless the operator says so in the
// command line, and the output says which mode it ran in either way.
//
// This command does not yet read the digest. It exists so that the Jira
// connection, the project configuration and the ticket format can each be
// verified separately, before anything automatic is pointed at a real finding.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

const (
	exitOK      = 0
	exitFailure = 1
)

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[jira] "+format+"\n", a...)
}

func die(format string, a ...any) int {
	logf("ERROR: "+format, a...)
	return exitFailure
}

func main() { os.Exit(run()) }

func run() int {
	check := flag.Bool("check", false,
		"read-only: verify credentials, project, issue type and required fields")
	testTicket := flag.Bool("test-ticket", false,
		"build a clearly-labelled test ticket")
	forReal := flag.Bool("for-real", false,
		"actually create it; without this, nothing is written")
	flag.Parse()

	if !*check && !*testTicket {
		flag.Usage()
		return die("nothing to do - pass --check or --test-ticket")
	}

	// fleet.env, then the environment wins, same as every other lane. A
	// missing file is zero variables, not an error: the lane may be
	// configured entirely from the unit's Environment= lines.
	if n := fleetenv.Load(); n > 0 {
		logf("config: %s (%d variables)", fleetenv.Path(), n)
	}

	cfg, err := config.LoadJira()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}

	c := jira.New(cfg.JiraBaseURL, cfg.JiraEmail, cfg.JiraAPIToken)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if *check {
		if rc := doCheck(ctx, c, cfg); rc != exitOK {
			return rc
		}
	}
	if *testTicket {
		return doTestTicket(ctx, c, cfg, *forReal)
	}
	return exitOK
}

// doCheck answers "would a create succeed?" without creating anything.
func doCheck(ctx context.Context, c *jira.Client, cfg config.Config) int {
	who, err := c.Myself(ctx)
	if err != nil {
		return die("credentials rejected: %s", safelog.Line(err.Error()))
	}
	// Printed because an API token carries every permission its account has.
	// "Which account is this" is the blast-radius question, and a token
	// belonging to a departed admin looks exactly like a service account
	// until you read the name.
	logf("authenticated as %s <%s> active=%v",
		safelog.Line(who.DisplayName), safelog.Line(who.Email), who.Active)

	logf("project: %s   issue type: %s",
		safelog.Line(cfg.JiraProjectKey), safelog.Line(cfg.JiraIssueType))

	if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
		// Not fatal to --check. The point of --check is to report the state,
		// and "configured to read but not write" is a state worth reporting
		// clearly rather than exiting on.
		logf("  WRITE GATE CLOSED: %s", safelog.Line(err.Error()))
	} else {
		logf("  write gate OPEN for %s", safelog.Line(cfg.JiraProjectKey))
	}

	types, err := c.IssueTypes(ctx, cfg.JiraProjectKey)
	if err != nil {
		return die("listing issue types for %s: %s",
			safelog.Line(cfg.JiraProjectKey), safelog.Line(err.Error()))
	}
	it, err := jira.ResolveIssueType(types, cfg.JiraIssueType)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	logf("  issue type %q resolves to id %s", safelog.Line(it.Name), safelog.Line(it.ID))

	fields, err := c.CreateFields(ctx, cfg.JiraProjectKey, it.ID)
	if err != nil {
		return die("reading create fields: %s", safelog.Line(err.Error()))
	}

	var required []string
	for _, f := range fields {
		if f.Required {
			label := f.FieldID
			if f.Schema.Custom != "" {
				// A required custom field is the thing most likely to break a
				// create, and its id tells you nothing - print the name too.
				label = fmt.Sprintf("%s (%s)", f.FieldID, f.Name)
			}
			required = append(required, label)
		}
	}
	sort.Strings(required)

	logf("  create screen: %d fields, %d required", len(fields), len(required))
	if len(required) == 0 {
		logf("  NOTE: no required fields reported, including summary. Treat with")
		logf("        suspicion - verify with one --test-ticket --for-real.")
	}
	for _, r := range required {
		known := r == "project" || r == "summary" || r == "issuetype" ||
			strings.HasPrefix(r, "description")
		mark := "  "
		if !known {
			// This is the Service Management trap: a required request-type or
			// similar custom field that cti-jira does not set, so every create
			// 400s until fleet.env or the screen changes.
			mark = "<-"
		}
		logf("    required: %-40s %s", safelog.Line(r), mark)
	}
	if len(required) > 0 {
		logf("  anything marked <- is NOT set by this command and will fail a create")
	}

	// Exercise SEARCH too, because --check is worthless if it only proves the
	// read paths that happen to be on a different API version.
	//
	// This is how /rest/api/2/search being removed was found: at the moment of
	// creating a ticket, as a 410 after the operator had already committed to
	// --for-real. A duplicate check runs before every create, so a broken
	// search breaks the whole lane - and a preflight that does not touch it is
	// a preflight that lies. The query matches nothing on purpose.
	hits, err := c.Search(ctx, jira.FindJQL(cfg.JiraProjectKey, "CVE-1900-00000"), 1)
	if err != nil {
		return die("the duplicate-detection search failed: %s", safelog.Line(err.Error()))
	}
	logf("  duplicate search works (%d matches for the test CVE)", len(hits))
	return exitOK
}

// testFinding is obviously synthetic. A test ticket that looks like a real
// finding is one somebody acts on.
func testFinding(now time.Time) jira.Finding {
	return jira.Finding{
		CVE:      "CVE-1900-00000",
		Title:    "CTI AGENT TEST TICKET - not a real vulnerability, please close",
		QIDs:     []string{"999999"},
		Hosts:    []string{"test-host-1.invalid", "test-host-2.invalid"},
		KEV:      false,
		Severity: 1,
		CVSS:     "0.0",
		QQL:      `vulnerabilities.vulnerability.qid:999999`,
		// A deliberately absurd CVE year and .invalid hostnames, which RFC
		// 2606 reserves precisely so they cannot resolve to anything real.
		FirstSeen: now,
	}
}

func doTestTicket(ctx context.Context, c *jira.Client, cfg config.Config, forReal bool) int {
	now := time.Now().UTC()
	f := testFinding(now)
	csvName := jira.CSVName(f.CVE, now)

	summary := jira.Summary(f, now)
	desc := jira.Description(f, now, csvName)
	csvBody, err := jira.HostCSV(f)
	if err != nil {
		return die("building the host CSV: %s", safelog.Line(err.Error()))
	}

	if !forReal {
		// stdout, as a single JSON object, so this is greppable and diffable
		// and so a future runner can parse the same shape.
		out, _ := json.MarshalIndent(map[string]any{
			"mode":        "dry-run",
			"created":     false,
			"project":     cfg.JiraProjectKey,
			"issue_type":  cfg.JiraIssueType,
			"summary":     summary,
			"labels":      jira.Labels(f),
			"find_jql":    jira.FindJQL(cfg.JiraProjectKey, f.CVE),
			"attachment":  csvName,
			"description": desc,
			"csv":         string(csvBody),
		}, "", "  ")
		fmt.Println(string(out))
		logf("DRY RUN - nothing created. Add --for-real to file it.")
		return exitOK
	}

	if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}

	// Duplicate check before create, even for a test ticket - partly to
	// exercise the path that matters most in production, and partly because
	// running --for-real twice should not leave two test tickets behind.
	existing, err := c.Search(ctx, jira.FindJQL(cfg.JiraProjectKey, f.CVE), 5)
	if err != nil {
		return die("searching for an existing ticket: %s", safelog.Line(err.Error()))
	}
	if len(existing) > 0 {
		logf("a ticket for %s already exists: %s (%s)",
			f.CVE, existing[0].Key, c.BrowseURL(existing[0].Key))
		logf("nothing created. Close and delete it to run this again.")
		out, _ := json.Marshal(map[string]any{
			"mode": "for-real", "created": false,
			"reason": "duplicate", "key": existing[0].Key,
		})
		fmt.Println(string(out))
		return exitOK
	}

	res, err := c.CreateIssue(ctx, jira.IssueRequest{
		ProjectKey:  cfg.JiraProjectKey,
		IssueType:   cfg.JiraIssueType,
		Summary:     summary,
		Description: desc,
		Labels:      jira.Labels(f),
	})
	if err != nil {
		return die("creating the ticket: %s", safelog.Line(err.Error()))
	}
	logf("created %s - %s", res.Key, c.BrowseURL(res.Key))

	// The attachment is reported separately rather than failing the run. The
	// ticket exists either way, and "the ticket was filed but the CSV did
	// not attach" is a different problem from "no ticket was filed" - running
	// this again would file a second ticket to fix the first one's upload.
	attached := true
	if err := c.Attach(ctx, res.Key, csvName, csvBody); err != nil {
		attached = false
		logf("WARNING: ticket %s was created but the CSV did not attach: %s",
			res.Key, safelog.Line(err.Error()))
		logf("         the ticket is fine; the attachment path needs fixing")
	} else {
		logf("attached %s", csvName)
	}

	out, _ := json.Marshal(map[string]any{
		"mode": "for-real", "created": true,
		"key": res.Key, "url": c.BrowseURL(res.Key),
		"attached": attached, "attachment": csvName,
	})
	fmt.Println(string(out))

	logf("NOW CHECK, BY HAND: does %s appear in the queue your team works from?", res.Key)
	logf("A Service Management project can accept an issue over the plain API")
	logf("and leave it out of the agent queues, which is invisible from here.")
	return exitOK
}
