// cti-vmscan combines the week's Qualys VM scan-result notices into one report.
//
//	cti-vmscan --out w.html --text-out w.txt --subject-out w.subject --seen-out w.seen.json
//	cti-vmscan --commit-seen w.seen.json     # after the send: let cleanup archive them
//
// It reads the notices that arrived in the CTI mailbox over the last week
// (Graph, read-only), takes the newest result for each scheduled scan it is
// told to expect (--scans, or VMSCAN_SCANS), and renders ONE report with the
// scans kept separate. A scheduled scan with no result is the first thing the
// report says. It sends nothing: run-vmscan hands the files to cti-mailer.
//
// # WHAT "USED" MEANS FOR THE MAILBOX CLEANUP
//
// --seen-out lists the results notices of the expected scans this report
// covered. run-vmscan commits that file only after a real send, so "the lane
// has used it" means the report reached its audience, and the mailbox cleanup
// archives those notices 48 hours later. The other Qualys notices for the same
// scan ("Scan Completed", the owner-only notification, "scheduled to start")
// carry nothing the report uses and are left where they are.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/mailbox"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/vmscan"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() { os.Exit(run()) }

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "[vmscan] "+format+"\n", a...) }

func die(format string, a ...any) int {
	logf("error  : "+format, a...)
	return exitErr
}

func run() int {
	since := flag.Duration("since", 7*24*time.Hour, "how far back to look for scan-result notices")
	scansFlag := flag.String("scans", "",
		"comma-separated titles of the scheduled scans to combine (default VMSCAN_SCANS, "+
			"else the two weekly scans)")
	out := flag.String("out", "", "write the HTML here")
	textOut := flag.String("text-out", "", "write the plain-text version here")
	subjectOut := flag.String("subject-out", "", "write the subject line here")
	seenOut := flag.String("seen-out", "",
		"write the notices this report covered here, for --commit-seen after the send")
	commitSeen := flag.String("commit-seen", "",
		"record a --seen-out file in the processed log the mailbox cleanup reads; then exit")
	flag.Parse()

	if *commitSeen != "" {
		return doCommitSeen(*commitSeen)
	}

	fleetenv.Load()
	cfg, err := config.LoadGraphOnly()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	expected := expectedScans(*scansFlag)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	g := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	// HTML: the report link is in an <a href> that Graph's text conversion drops.
	msgs, err := g.RecentMessagesHTML(ctx, cfg.GraphMailbox, cfg.GraphFolder, time.Now().Add(-*since))
	if err != nil {
		return die("reading the mailbox: %s", safelog.Line(err.Error()))
	}

	scans, seen, problems := collect(msgs, expected)
	for _, p := range problems {
		logf("warn   : %s", safelog.Line(p))
	}
	week := vmscan.Combine(scans, expected)
	for _, m := range week.Missing {
		logf("warn   : no result for %q in the last %s", safelog.Line(m), *since)
	}
	logf("scans  : %d notice(s) read, %d scheduled scan(s) reported, %d missing, %d other",
		len(scans), len(week.Scans), len(week.Missing), len(week.Other))

	org := strings.TrimSpace(os.Getenv("FLEET_ORG"))
	if org == "" {
		org = "Security"
	}
	block := vmscan.Render(week, org, time.Now())

	for path, content := range map[string]string{*out: block.HTML, *textOut: block.Text, *subjectOut: block.Subject + "\n"} {
		if path == "" {
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return die("writing %s: %s", safelog.Line(path), safelog.Line(err.Error()))
		}
		logf("wrote  : %s", safelog.Line(path))
	}
	fmt.Println(block.Subject)

	if *seenOut != "" {
		if err := writeSeen(*seenOut, seen); err != nil {
			logf("warn   : could not write %s: %s - these notices will not be archived this week",
				safelog.Line(*seenOut), safelog.Line(err.Error()))
		}
	}
	return exitOK
}

// expectedScans is the scan titles to combine: the flag, else VMSCAN_SCANS,
// else the two weeklies.
func expectedScans(flagValue string) []string {
	raw := strings.TrimSpace(flagValue)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("VMSCAN_SCANS"))
	}
	if raw == "" {
		return vmscan.DefaultScans
	}
	var out []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// collect turns mailbox messages into scans, and records which messages were
// the expected scans' results.
func collect(msgs []graph.Message, expected []string) ([]vmscan.Scan, []mailbox.Processed, []string) {
	var p vmscan.Provider
	var scans []vmscan.Scan
	var seen []mailbox.Processed
	var problems []string
	want := map[string]bool{}
	for _, t := range expected {
		want[strings.ToLower(strings.Join(strings.Fields(t), " "))] = true
	}
	for _, m := range msgs {
		// Before the self-sent skip: a lookalike From the mailbox's own address
		// would otherwise fall into it silently. A correctly signed message
		// really is ours and is not checked.
		if !m.SelfVerified && p.Lookalike(m.From, m.Subject) {
			problems = append(problems, fmt.Sprintf(
				"%q has the Qualys results subject but came from %s, so it was not read. "+
					"If the scan is real, its schedule's notification From Address is probably "+
					"set to this mailbox; set it to qualys@qualys.net", short(m.Subject), safelog.Line(m.From)))
			continue
		}
		if m.SelfSent || !p.Recognises(m.From, m.Subject) {
			continue
		}
		body := m.BodyHTML
		if body == "" {
			body = m.BodyText
		}
		s, probs := p.Parse(body)
		for _, pr := range probs {
			problems = append(problems, fmt.Sprintf("%s: %s", short(m.Subject), pr))
		}
		s.MessageID, s.Received = m.ID, m.ReceivedDateTime
		scans = append(scans, s)
		// Claimed for the cleanup only when it is one of the scans this report
		// covers and it parsed into a scan: a notice that did not parse was not
		// reported on, and stays in the inbox for a person.
		if s.Ref != "" && want[strings.ToLower(strings.Join(strings.Fields(s.Title), " "))] {
			seen = append(seen, mailbox.Processed{
				ID: m.ID, Subject: m.Subject, Received: m.ReceivedDateTime,
				AutoReply: m.IsAutoReply(), Owner: mailbox.OwnerVMScan,
			})
		}
	}
	return scans, seen, problems
}

func short(s string) string { return safelog.LineMax(s, 60) }

func writeSeen(path string, seen []mailbox.Processed) error {
	b, err := json.MarshalIndent(mailbox.Log{Entries: seen}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// doCommitSeen merges a --seen-out file into this lane's processed log.
func doCommitSeen(path string) int {
	dest := mailbox.OwnerLogPath(mailbox.OwnerVMScan)
	if dest == "" {
		return die("FLEET_HOME is not set, so there is no state directory to record in")
	}
	// #nosec G304 -- the runner's own --seen-out file under $FLEET_HOME/state.
	b, err := os.ReadFile(path)
	if err != nil {
		return die("reading %s: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	var pending mailbox.Log
	if err := json.Unmarshal(b, &pending); err != nil {
		return die("%s does not parse: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	store := mailbox.NewStore(dest)
	l, err := store.Load()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	for i := range pending.Entries {
		pending.Entries[i].Owner = mailbox.OwnerVMScan
	}
	store.Record(l, pending.Entries)
	if err := store.Save(l); err != nil {
		return die("saving %s: %s", safelog.Line(dest), safelog.Line(err.Error()))
	}
	logf("seen   : %d notice(s) recorded for the mailbox cleanup", len(pending.Entries))
	return exitOK
}
