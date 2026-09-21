// cti-mailbox tidies the shared CTI mailbox once a day.
//
// Processed advisories go to Archive. Out-of-office auto-replies go to Deleted
// Items. Anything the agent has no record of reading is left exactly where it
// is, and counted.
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
// IT REFUSES TO RUN ON A DAY NOTHING WAS PROCESSED. The operator's rule is
// "only after a CTI email is processed". A day where the agent read nothing -
// because it broke, because the mailbox went quiet, because a credential
// expired - is a day where the safest thing to do with the inbox is nothing.
// Exits 0 in that case: a working refusal is not a failure, and returning
// non-zero would make systemd mark the unit failed and cti-alert email about
// a lane that behaved correctly.
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
		fmt.Fprintf(os.Stderr, "cti-mailbox: config: %v\n", err)
		fmt.Fprintf(os.Stderr, "cti-mailbox: read %s\n", fleetenv.Path())
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
		fmt.Fprintf(os.Stderr, "cti-mailbox: %v\n", err)
		fmt.Fprintln(os.Stderr,
			"cti-mailbox: refusing to act on a processed-message log that does "+
				"not parse. Delete it and let the next digest rebuild it; the "+
				"inbox will simply not be tidied until then.")
		return exitFailure
	}

	loc := timezone()
	ok, todayCount := l.ProcessedToday(time.Now(), loc)
	if !ok {
		fmt.Printf("No CTI email has been processed today (%s). "+
			"Nothing to clean up - leaving the mailbox alone.\n",
			time.Now().In(loc).Format("2006-01-02"))
		return exitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Read the inbox over the same window the agent uses, so the two lanes
	// see the same set of messages. Anything older has aged out of the
	// processed log anyway and will be left alone.
	since := time.Now().Add(-cfg.GraphLookback)
	g := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	msgs, err := g.RecentMessages(ctx, cfg.GraphMailbox, cfg.GraphFolder, since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cti-mailbox: reading %s: %v\n", cfg.GraphMailbox, err)
		return exitFailure
	}

	candidates := make([]mailbox.Candidate, 0, len(msgs))
	for _, m := range msgs {
		candidates = append(candidates, mailbox.Candidate{
			ID: m.ID, Subject: m.Subject,
			Received: m.ReceivedDateTime, AutoReply: m.IsAutoReply(),
		})
	}
	plan := mailbox.Plan(candidates, l.Index())
	counts := mailbox.Summarise(plan)

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
		line := fmt.Sprintf("  %-7s %s  (%s)", d.Action, truncate(d.Subject, 60), d.Reason)
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
			fmt.Printf("%s -> FAILED: %v\n", line, err)
			continue
		}
		moved++
		fmt.Printf("%s -> moved (new id %s)\n", line, truncate(newID, 16))
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
		fmt.Fprintf(os.Stderr, "cti-mailbox: %v\n", err)
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
