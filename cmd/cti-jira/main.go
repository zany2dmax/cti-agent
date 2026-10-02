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
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/qualys"
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
	fromEnriched := flag.String("from-enriched", "",
		"file tickets for the KEV and Sev5 findings in this enriched JSON")
	approve := flag.Bool("approve", false,
		"also file the findings that would otherwise wait for a human: "+
			"Sev5 findings that are not on CISA KEV")
	flag.Parse()

	if !*check && !*testTicket && *fromEnriched == "" {
		flag.Usage()
		return die("nothing to do - pass --check, --test-ticket or --from-enriched")
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
	if *fromEnriched != "" {
		return doFromEnriched(ctx, c, cfg, *fromEnriched, *forReal, *approve)
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
		_, rc := updateExisting(ctx, c, existing[0], f, csvBody, now)
		return rc
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

	// Write the exposure state AFTER the ticket exists. A state record for a
	// ticket that was never created would make the next run think it had
	// already reported hosts nobody has seen.
	st := jira.StateFrom(f, res.Key, now)
	if err := c.SetProperty(ctx, res.Key, jira.PropertyKey, st); err != nil {
		// Not fatal. The ticket is filed and that was the point; a missing
		// state record costs one skipped drift comparison next run, which
		// then rewrites it.
		logf("WARNING: could not record exposure state on %s: %s",
			res.Key, safelog.Line(err.Error()))
	}

	out, _ := json.Marshal(map[string]any{
		"mode": "for-real", "created": true,
		"key": res.Key, "url": c.BrowseURL(res.Key),
		"attached": attached, "attachment": csvName,
		"hosts": f.Count(), "hosts_hash": st.HostsHash,
	})
	fmt.Println(string(out))

	logf("NOW CHECK, BY HAND: does %s appear in the queue your team works from?", res.Key)
	logf("A Service Management project can accept an issue over the plain API")
	logf("and leave it out of the agent queues, which is invisible from here.")
	return exitOK
}

// updateExisting is what happens on every run after the first: the ticket is
// already there, and the question is whether anything changed enough to say.
//
// The old behaviour was to print "already exists" and stop, which meant a CVE
// spreading from 441 hosts to 500 looked exactly like one that had not moved.
// A ticket that snapshots a single morning and never updates is worse than no
// ticket, because it looks current.
func updateExisting(ctx context.Context, c *jira.Client, issue jira.Issue,
	f jira.Finding, csvBody []byte, now time.Time) (string, int) {

	key := issue.Key
	logf("ticket for %s already exists: %s (%s)", f.CVE, key, c.BrowseURL(key))

	var prev jira.ExposureState
	found, err := c.GetProperty(ctx, key, jira.PropertyKey, &prev)
	if err != nil {
		// A malformed or unreadable property is reported and treated as
		// absent. It costs one comparison; it must not kill the run.
		logf("WARNING: %s", safelog.Line(err.Error()))
	}
	var prevPtr *jira.ExposureState
	if found {
		prevPtr = &prev
	}

	// A CLOSED ticket with live detections is a human question, not an
	// automation one. Somebody closed it deliberately - exception,
	// compensating control, a replacement ticket - and software that reverses
	// that every night is software that gets switched off. Say it once.
	if issue.IsDone() && f.Count() > 0 {
		if found && !prev.ClosedButDetectedAt.IsZero() {
			logf("closed, still detected on %d host(s) - already noted on %s, saying nothing",
				f.Count(), prev.ClosedButDetectedAt.Format("2006-01-02"))
			emit(map[string]any{"mode": "for-real", "created": false,
				"reason": "closed-but-detected-already-noted", "key": key})
			return key, exitOK
		}
		if err := c.AddComment(ctx, key, jira.ClosedButDetectedComment(f, now)); err != nil {
			return key, die("commenting on %s: %s", key, safelog.Line(err.Error()))
		}
		st := jira.StateFrom(f, key, now)
		st.ClosedButDetectedAt = now
		if err := c.SetProperty(ctx, key, jira.PropertyKey, st); err != nil {
			logf("WARNING: could not record state on %s: %s", key, safelog.Line(err.Error()))
		}
		logf("closed ticket still has detections - noted once, not reopened")
		emit(map[string]any{"mode": "for-real", "created": false,
			"reason": "closed-but-detected", "key": key, "commented": true})
		return key, exitOK
	}

	d := jira.DiffExposure(prevPtr, f, now)
	if !d.Material() {
		// Still record state, so a shrink today is visible in the comparison
		// that a growth tomorrow produces. Quiet is not the same as lost.
		st := jira.StateFrom(f, key, now)
		if found {
			st.ClosedButDetectedAt = prev.ClosedButDetectedAt
		}
		if err := c.SetProperty(ctx, key, jira.PropertyKey, st); err != nil {
			logf("WARNING: could not record state on %s: %s", key, safelog.Line(err.Error()))
		}
		switch {
		case d.FirstLook:
			logf("no stored state - recorded %d host(s), no comment (this is not a discovery)",
				f.Count())
		default:
			logf("no material change (%d -> %d hosts) - state updated, no comment",
				d.CountBefore, d.CountAfter)
		}
		emit(map[string]any{"mode": "for-real", "created": false,
			"reason": "no-material-change", "key": key,
			"hosts": f.Count(), "commented": false})
		return key, exitOK
	}

	csvName := jira.CSVName(f.CVE, now)
	if err := c.AddComment(ctx, key, jira.DriftComment(d, f, csvName, now)); err != nil {
		return key, die("commenting on %s: %s", key, safelog.Line(err.Error()))
	}
	logf("commented on %s: %d -> %d hosts, +%d new, +%d new QID(s)",
		key, d.CountBefore, d.CountAfter, len(d.NewHosts), len(d.NewQIDs))

	attached := true
	// len(Hosts), not Count(): this asks "is there a CSV worth uploading",
	// and a truncated scan can report a nonzero count with no names.
	if len(f.Hosts) > 0 {
		if err := c.Attach(ctx, key, csvName, csvBody); err != nil {
			attached = false
			logf("WARNING: comment posted but the CSV did not attach: %s",
				safelog.Line(err.Error()))
		}
	}

	// State last. If this fails the comment has still gone out, and the next
	// run re-reports the same drift - noisy, but never silent. The opposite
	// ordering would record hosts as reported that nobody was told about.
	st := jira.StateFrom(f, key, now)
	if found {
		st.ClosedButDetectedAt = prev.ClosedButDetectedAt
	}
	if err := c.SetProperty(ctx, key, jira.PropertyKey, st); err != nil {
		logf("WARNING: could not record state on %s - the next run will "+
			"repeat this comment: %s", key, safelog.Line(err.Error()))
	}

	emit(map[string]any{"mode": "for-real", "created": false,
		"reason": "updated", "key": key, "url": c.BrowseURL(key),
		"commented": true, "attached": attached,
		"hosts_before": d.CountBefore, "hosts_after": d.CountAfter,
		"new_hosts": len(d.NewHosts), "new_qids": len(d.NewQIDs),
		"resolved": d.Resolved,
	})
	return key, exitOK
}

func emit(v map[string]any) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

// doFromEnriched is the production path: file and update tickets for the KEV
// and Sev5 findings in the digest's own output.
//
// Ordering inside run-digest matters and is deliberate - this runs AFTER
// enrich and BEFORE brief, so the ticket keys exist by the time the email is
// rendered. The consequence is that this lane sits between the fleet and its
// daily security email, so every failure path below returns exitOK. A Jira
// outage must cost tickets, never the digest.
func doFromEnriched(ctx context.Context, c *jira.Client, cfg config.Config,
	path string, forReal, approve bool) int {

	now := time.Now().UTC()

	ef, err := loadEnriched(path)
	if err != nil {
		logf("WARNING: %s - no tickets this run", safelog.Line(err.Error()))
		return exitOK
	}

	q := qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword,
		cfg.QualysKBCachePath, cfg.QualysKBMaxAge)
	if _, err := q.LoadOrBuildKBCache(ctx, cfg.QualysKBCachePath); err != nil {
		logf("WARNING: scanner KB cache unavailable (%s) - no tickets this run",
			safelog.Line(err.Error()))
		return exitOK
	}

	fill := func(ctx context.Context, cve string) (vulnlookup.Result, error) {
		return q.LookupCVE(ctx, cve)
	}
	findings := selectForTicketing(ctx, ef.Findings, fill,
		func(format string, a ...any) { logf("WARNING: "+format, a...) })

	logf("%d of %d findings qualify for a ticket (KEV or Sev5, and present)",
		len(findings), len(ef.Findings))

	tm := TicketMap{Generated: now.Format(time.RFC3339), Tickets: map[string]TicketRef{}}

	for _, f := range findings {
		ref, err := fileOrUpdate(ctx, c, cfg, f, now, forReal, approve)
		if err != nil {
			// One bad ticket must not stop the rest, and must not stop the
			// digest. Named, counted, carried on.
			logf("WARNING: %s: %s", f.CVE, safelog.Line(err.Error()))
			continue
		}
		if ref.Key != "" {
			tm.Tickets[f.CVE] = ref
			// Close the loop back to the findings table, so the orchestrator
			// stops reporting a ticketed CVE as un-actioned. Only on a real
			// run: a dry run must not write to the database either.
			if forReal {
				recordRemediationNote(f.CVE, RemediationNote(ref, now),
					func(format string, a ...any) { logf("WARNING: "+format, a...) })
			}
		}
	}

	out := TicketMapPath(path)

	// A DRY RUN MUST NOT TOUCH THE MAP.
	//
	// It used to write it unconditionally, so a dry run after a real one
	// replaced a map full of ticket keys with an empty one - and the digest,
	// which reads that file, would then render with no tickets at all. A
	// preview that destroys the thing it is previewing is worse than no
	// preview: the damage is silent and shows up in an email.
	if !forReal {
		logf("DRY RUN - %s left untouched", out)
		return exitOK
	}

	if err := writeTicketMap(out, tm); err != nil {
		logf("WARNING: %s - the digest will render without ticket keys",
			safelog.Line(err.Error()))
		return exitOK
	}
	logf("wrote %d ticket reference(s) to %s", len(tm.Tickets), out)
	return exitOK
}

// fileOrUpdate creates a ticket, or updates the one that already exists.
func fileOrUpdate(ctx context.Context, c *jira.Client, cfg config.Config,
	f jira.Finding, now time.Time, forReal, approve bool) (TicketRef, error) {

	existing, err := c.Search(ctx, jira.FindJQL(cfg.JiraProjectKey, f.CVE), 5)
	if err != nil {
		return TicketRef{}, fmt.Errorf("searching for an existing ticket: %w", err)
	}

	csvBody, err := jira.HostCSV(f)
	if err != nil {
		return TicketRef{}, fmt.Errorf("building the host CSV: %w", err)
	}

	if len(existing) > 0 {
		issue := existing[0]
		if !forReal {
			logf("DRY RUN %s: would update %s (%d hosts)", f.CVE, issue.Key, f.Count())
			return TicketRef{Key: issue.Key, URL: c.BrowseURL(issue.Key),
				Status: issue.Fields.Status.Name}, nil
		}
		key, rc := updateExisting(ctx, c, issue, f, csvBody, now)
		if rc != exitOK {
			return TicketRef{}, fmt.Errorf("updating %s", key)
		}
		return TicketRef{Key: key, URL: c.BrowseURL(key),
			Status: issue.Fields.Status.Name}, nil
	}

	// A non-KEV Sev5 is the fleet's own judgement rather than an external
	// deadline, so it waits for a person - unless a person said so.
	//
	// --approve is the person saying so, and it is a FLAG rather than a
	// config setting on purpose: the scheduled run in run-digest does not
	// pass it, so the automatic path can only ever file KEV entries. Putting
	// this in fleet.env would make "the fleet decided to file this" a thing
	// that happens at 10:00 with nobody watching.
	if jira.NeedsApproval(f) && !approve {
		logf("%s is Sev5 but not on KEV - held for approval "+
			"(re-run with --approve to file it)", f.CVE)
		return TicketRef{}, nil
	}

	if !forReal {
		logf("DRY RUN %s: would file a new ticket (%d hosts, %d QIDs)",
			f.CVE, f.Count(), len(f.QIDs))
		return TicketRef{}, nil
	}

	if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
		return TicketRef{}, err
	}

	csvName := jira.CSVName(f.CVE, now)
	res, err := c.CreateIssue(ctx, jira.IssueRequest{
		ProjectKey:  cfg.JiraProjectKey,
		IssueType:   cfg.JiraIssueType,
		Summary:     jira.Summary(f, now),
		Description: jira.Description(f, now, csvName),
		Labels:      jira.Labels(f),
	})
	if err != nil {
		return TicketRef{}, fmt.Errorf("creating the ticket: %w", err)
	}
	logf("filed %s for %s (%d hosts) - %s", res.Key, f.CVE, f.Count(), c.BrowseURL(res.Key))

	if len(f.Hosts) > 0 {
		if err := c.Attach(ctx, res.Key, csvName, csvBody); err != nil {
			logf("WARNING: %s was created but the CSV did not attach: %s",
				res.Key, safelog.Line(err.Error()))
		}
	}
	st := jira.StateFrom(f, res.Key, now)
	if err := c.SetProperty(ctx, res.Key, jira.PropertyKey, st); err != nil {
		logf("WARNING: could not record exposure state on %s: %s",
			res.Key, safelog.Line(err.Error()))
	}
	return TicketRef{Key: res.Key, URL: c.BrowseURL(res.Key), Created: true}, nil
}
