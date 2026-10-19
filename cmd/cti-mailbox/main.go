// cti-mailbox tidies the shared CTI mailbox once a day.
//
// Mail a lane owns and has read goes to Archive: CTI advisories the digest
// took a CVE from, Qualys WAS notifications the application-security weekly
// reported on. Automatic replies go to Deleted Items, read or not. Anything
// else is left exactly where it is, and counted.
//
//	cti-mailbox                 show what would happen, move nothing
//	cti-mailbox --for-real      actually move
//	cti-mailbox --json out.json record the plan for later inspection
//
// # THIS IS THE ONLY THING IN THE FLEET THAT MODIFIES THE MAILBOX
//
// Everything else reads mail or sends it. This moves other people's mail, on a
// timer, with nobody watching, which makes it the piece with the most room to
// do quiet damage. Three properties follow from that, and none of them is
// optional:
//
// DRY RUN IS THE DEFAULT. Moving requires --for-real. A flag that has to be
// added to cause an effect cannot be triggered by a misconfigured unit file.
//
// NOTHING HERE CAN PERMANENTLY DELETE. internal/graph offers move-to-folder
// and nothing else; Graph's DELETE and purge endpoints are not implemented.
// "Delete" means Deleted Items, which is recoverable, and emptying that folder
// is a person's job.
//
// IT ARCHIVES NOTHING ON A DAY NOTHING WAS PROCESSED. The operator's rule is
// "only after a CTI email is processed". A day where the agent read nothing -
// because it broke, because the mailbox went quiet, because a credential
// expired - is a day where nothing should be filed away. Automatic replies
// are still deleted (since 1.3.2): that needs no fleet health, and skipping
// whole days is how out-of-office replies piled up in the inbox.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/mailbox"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

const (
	exitOK      = 0
	exitFailure = 1
)

func main() { os.Exit(run()) }

func run() int {
	forReal := flag.Bool("for-real", false,
		"actually move the messages. Without this nothing is modified")
	jsonOut := flag.String("json", "",
		"write the plan here, so what happened can be checked afterwards")
	backlog := flag.Int("backlog-threshold", 25,
		"report when this many inbox messages have no processing record. "+
			"A growing backlog is what 'the agent stopped reading the mailbox' "+
			"looks like from outside")
	timeout := flag.Duration("timeout", 2*time.Minute, "overall Graph timeout")
	lookback := flag.Duration("lookback", 0,
		"how far back to look this run, e.g. 720h for a one-off sweep of old "+
			"auto-replies; 0 means MAILBOX_LOOKBACK_HOURS. Archiving still needs "+
			"a processing record, and records expire after 14 days")
	flag.Parse()

	// fleet.env, for a run by hand. The cti-agent wrapper exports only the
	// FLEET_* layout, so without this every credential reads as missing even
	// though it is sitting in the file the wrapper just pointed at.
	fleetenv.Load()

	// Graph only. This lane reads the inbox and moves messages; it never asks
	// the scanner anything, so demanding Qualys credentials would fail a run
	// for settings it has no use for.
	cfg, err := config.LoadGraphOnly()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cti-mailbox: config: %s\n", safelog.Line(err.Error()))
		fmt.Fprintf(os.Stderr, "cti-mailbox: read %s\n", safelog.Line(fleetenv.Path()))
		return exitFailure
	}

	logPath := mailbox.LogPath()
	if logPath == "" {
		fmt.Fprintln(os.Stderr,
			"cti-mailbox: FLEET_HOME is not set, so there is no processed-message "+
				"log to check against. Refusing to touch the mailbox - this lane "+
				"has no way to tell a processed advisory from an unread one.")
		return exitFailure
	}
	store := mailbox.NewStore(logPath)
	l, err := store.Load()
	if err != nil {
		// A corrupt log is a hard stop, not a warning. Continuing would mean
		// acting on a partial set of message IDs, and the failure mode of
		// "some of the log parsed" is silently moving the wrong things.
		fmt.Fprintf(os.Stderr, "cti-mailbox: %s\n", safelog.Line(err.Error()))
		fmt.Fprintln(os.Stderr,
			"cti-mailbox: refusing to act on a processed-message log that does "+
				"not parse. Delete it and let the next digest rebuild it; the "+
				"inbox will simply not be tidied until then.")
		return exitFailure
	}

	// The lanes that own mail of their own. Missing is normal (the lane has
	// not run yet, or is not installed); corrupt is the same hard stop as the
	// digest's log, for the same reason.
	var owned []*mailbox.Log
	for _, owner := range []string{mailbox.OwnerAppScan} {
		p := mailbox.OwnerLogPath(owner)
		ol, err := mailbox.NewStore(p).Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cti-mailbox: %s\n", safelog.Line(err.Error()))
			fmt.Fprintf(os.Stderr, "cti-mailbox: refusing to act on a %s log that "+
				"does not parse. Delete it; that lane's mail will simply not be "+
				"archived until its next run rebuilds it.\n", owner)
			return exitFailure
		}
		owned = append(owned, ol)
	}

	loc := timezone()
	ok, todayCount := l.ProcessedToday(time.Now(), loc)
	hold := ""
	if !ok {
		hold = "no CTI email has been processed today, so nothing is filed " +
			"away - the fleet may not be reading the mailbox"
		fmt.Printf("No CTI email has been processed today (%s): archiving "+
			"nothing, deleting automatic replies only.\n",
			time.Now().In(loc).Format("2006-01-02"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// A WIDER window than the agent uses, on purpose.
	//
	// These two used to share GRAPH_LOOKBACK_HOURS, and 24h for both made the
	// window exactly the interval between runs. A message arriving in the hour
	// before the cleanup fires is processed later that day, and by the next
	// run it has already fallen out of a 24h window - so it is never archived,
	// ever. The lane looked like it "sometimes missed some".
	//
	// MAILBOX_LOOKBACK_HOURS defaults to 336 (14 days, the processed log's
	// retention) since 1.3.2, so a weekly lane's mail is still in view.
	now := time.Now()
	window := cfg.MailboxLookback
	if *lookback != 0 {
		// Validated: auto-reply deletion needs no processing record, so a
		// typo'd window (168000h) would sweep years of mailbox.
		if err := config.ValidateLookback(*lookback); err != nil {
			fmt.Fprintf(os.Stderr, "cti-mailbox: --lookback: %s\n", safelog.Line(err.Error()))
			return exitFailure
		}
		window = *lookback
	}
	since := now.Add(-window)
	g := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	msgs, err := g.RecentMessages(ctx, cfg.GraphMailbox, cfg.GraphFolder, since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cti-mailbox: reading %s: %s\n",
			safelog.Line(cfg.GraphMailbox), safelog.Line(err.Error()))
		return exitFailure
	}

	candidates := make([]mailbox.Candidate, 0, len(msgs))
	for _, m := range msgs {
		candidates = append(candidates, mailbox.Candidate{
			ID: m.ID, Subject: m.Subject,
			Received: m.ReceivedDateTime, AutoReply: m.IsAutoReply(),
			// SelfVerified, not SelfSent: archiving is an action taken on
			// the strength of "we sent this", so it needs the signature, not
			// a From address or a header any sender could add.
			SelfSent: m.SelfVerified,
		})
	}
	plan := mailbox.PlanWith(candidates, mailbox.Merge(now, l.Index(), owned...),
		mailbox.Options{Now: now, MinAge: cfg.MailboxMinAge, HoldArchive: hold,
			SubjectGrace: cfg.GraphLookback})
	counts := mailbox.Summarise(plan)

	// State the window and the grace. "Why was that not archived?" should be
	// answerable from the output rather than from fleet.env, and the answer
	// is almost always one of these two numbers.
	fmt.Printf("  window %s, archive grace %s\n",
		window, cfg.MailboxMinAge)
	fmt.Printf("%s: %d message(s) in the window; %d CTI email(s) processed today\n",
		cfg.GraphMailbox, len(candidates), todayCount)
	// The leave count is split, because its two halves mean opposite things:
	// mail the agent read and is not responsible for is a security team's
	// ordinary inbox, while mail it never read is the number that indicates a
	// fault. One figure covering both told the operator nothing.
	fmt.Printf("  archive %d   delete %d   leave %d (%d never read, %d not CTI mail)\n",
		counts.Archive, counts.Delete, counts.Leave,
		counts.Unread, counts.Leave-counts.Unread)
	if !*forReal {
		fmt.Println("  DRY RUN - nothing was moved. Add --for-real to apply.")
	}

	var moved, failed int
	for i := range plan {
		d := &plan[i]
		// safelog.LineMax, not a bare truncate. d.Subject is the subject line
		// of somebody else's mail: attacker-controlled, because anyone can
		// send to a published security address. This lane prints it to the
		// journal on a timer with nobody watching, so a newline in a subject
		// would forge a journal record in the log an operator reads to find
		// out what this lane did with their mail - and this is the lane that
		// MOVES mail. The ingest lane was defended against exactly this while
		// this one was not; writing the threat model down is what found it.
		line := fmt.Sprintf("  %-7s %s  (%s)",
			d.Action, safelog.LineMax(d.Subject, 60), d.Reason)
		if d.Action == mailbox.ActionLeave || !*forReal {
			fmt.Println(line)
			continue
		}
		dest := graph.FolderArchive
		if d.Action == mailbox.ActionDelete {
			dest = graph.FolderDeletedItems
		}
		newID, err := g.MoveMessage(ctx, cfg.GraphMailbox, d.ID, dest)
		if err != nil {
			failed++
			fmt.Printf("%s -> FAILED: %s\n", line, safelog.Line(err.Error()))
			continue
		}
		moved++
		fmt.Printf("%s -> moved (new id %s)\n", line, safelog.LineMax(newID, 16))
	}

	if note := mailbox.BacklogNote(counts, *backlog); note != "" {
		fmt.Fprintf(os.Stderr, "cti-mailbox: %s\n", note)
	}

	if *jsonOut != "" {
		writePlan(*jsonOut, cfg.GraphMailbox, plan, counts, *forReal, moved, failed)
	}

	if *forReal {
		fmt.Printf("moved %d, failed %d, left %d\n", moved, failed, counts.Leave)
	}
	// A failed move is a real failure: the permission may be missing, and a
	// lane that reports success while moving nothing is the thing this whole
	// codebase keeps tripping over.
	if failed > 0 {
		return exitFailure
	}
	return exitOK
}

func timezone() *time.Location {
	if tz := os.Getenv("FLEET_TIMEZONE"); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
		fmt.Fprintf(os.Stderr,
			"cti-mailbox: FLEET_TIMEZONE=%q is not a known zone, using local\n", tz)
	}
	return time.Local
}

func writePlan(path, mbox string, plan []mailbox.Decision, counts mailbox.Counts,
	forReal bool, moved, failed int) {
	// #nosec G304 -- operator-supplied --json path; 0o600 because the plan
	// carries subject lines from a security mailbox.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cti-mailbox: %s\n", safelog.Line(err.Error()))
		return
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"mailbox": mbox, "at": time.Now().Format(time.RFC3339),
		"applied": forReal, "moved": moved, "failed": failed,
		"counts": counts, "plan": plan,
	})
}
