// cti-appscan builds the weekly application-security report from the scan
// notifications that arrived in the CTI mailbox.
//
//	cti-appscan --out report.html --text-out report.txt
//	cti-appscan --since 168h --no-detail      # counts only, no Qualys API
//	cti-appscan --subject-only                # for the runner's subject line
//
// # IT DOES NOT SEND
//
// Sending is cti-mailer's job, and cti-mailer holds the recipient gate. This
// writes files; the runner chains them to `cti-mailer --lane was`, which
// resolves WAS_TO against WAS_ALLOW_TO and refuses if either is unset.
//
// Keeping the two apart means a bug here cannot mail anything to anyone, and
// the one component that can send is the one place the allowlist lives.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/appscan/qualys"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() { os.Exit(run()) }

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[appscan] "+format+"\n", a...)
}

func die(format string, a ...any) int {
	logf("error  : "+format, a...)
	return exitErr
}

func run() int {
	since := flag.Duration("since", 7*24*time.Hour,
		"how far back to look for scan notifications")
	out := flag.String("out", "", "write the HTML here")
	textOut := flag.String("text-out", "", "write the plain-text version here")
	subjectOnly := flag.Bool("subject-only", false, "print the subject line and exit")
	noDetail := flag.Bool("no-detail", false,
		"skip the Qualys WAS API; report counts from the notifications only")
	flag.Parse()

	cfg, err := config.LoadGraphOnly()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	g := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	msgs, err := g.RecentMessages(ctx, cfg.GraphMailbox, cfg.GraphFolder,
		time.Now().Add(-*since))
	if err != nil {
		return die("reading the mailbox: %s", safelog.Line(err.Error()))
	}

	scans, problems := collect(msgs)
	for _, p := range problems {
		logf("warn   : %s", safelog.Line(p))
	}

	// Detail is optional by construction. The counts come from the
	// notification emails and need no credentials, so the API being down,
	// rate-limited or unlicensed costs per-finding detail and not the report.
	if !*noDetail {
		attachDetail(ctx, cfg, scans, time.Now().Add(-*since))
	}

	block := appscan.Render(scans, time.Now())

	if *subjectOnly {
		fmt.Println(block.Subject)
		return exitOK
	}

	logf("scans  : %d notification(s) in the last %s", len(scans), *since)
	logf("subject: %s", safelog.Line(block.Subject))

	for _, w := range []struct {
		path, body string
	}{
		{*out, block.HTML},
		{*textOut, block.Text},
	} {
		if w.path == "" {
			continue
		}
		// 0600: this names which applications have open Urgent findings and
		// which are scanned without authentication. Same handling as the VM
		// reports, for the same reason - it is a map of where to look.
		if err := os.WriteFile(w.path, []byte(w.body), 0o600); err != nil {
			return die("writing %s: %s", safelog.Line(w.path), safelog.Line(err.Error()))
		}
		logf("wrote  : %s", safelog.Line(w.path))
	}
	if *out == "" && *textOut == "" {
		fmt.Print(block.Text)
	}
	return exitOK
}

// providers is every scanner this lane understands.
//
// A slice rather than a single value so adding Invicti or Wiz is one entry and
// a parser, with nothing else to change: the loop below asks each in turn
// whether a message is theirs.
var providers = []appscan.Provider{qualys.Provider{}}

// collect turns mailbox messages into scan results.
func collect(msgs []graph.Message) ([]appscan.ScanResult, []string) {
	var scans []appscan.ScanResult
	var problems []string
	seen := map[string]bool{}

	for _, m := range msgs {
		// Our own mail is never input. The weekly report is not delivered to
		// this mailbox, but the daily digest is, and a lane that reads its own
		// output is a bug this fleet has already had once.
		if m.SelfSent {
			continue
		}
		for _, p := range providers {
			if !p.Recognises(m.From, m.Subject) {
				continue
			}
			s, probs := p.Parse(m.BodyText)
			for _, pr := range probs {
				problems = append(problems,
					fmt.Sprintf("%s: %s", shortSubject(m.Subject), pr))
			}
			if s.Reference == "" {
				// Without it the same notification cannot be recognised twice,
				// and Graph does return duplicates.
				problems = append(problems, shortSubject(m.Subject)+
					": no scan reference, so this result is not deduplicated")
			} else if seen[s.Reference] {
				continue
			}
			seen[s.Reference] = true

			if s.Finished.IsZero() {
				s.Finished = m.ReceivedDateTime
			}
			scans = append(scans, s)
			break
		}
	}

	// One scan per application: the newest. An application scanned twice in a
	// week would otherwise appear twice with different numbers, and a reader
	// has no way to tell which is current.
	return newestPerApp(scans), problems
}

func newestPerApp(scans []appscan.ScanResult) []appscan.ScanResult {
	sort.SliceStable(scans, func(i, j int) bool {
		return scans[i].Finished.After(scans[j].Finished)
	})
	var out []appscan.ScanResult
	seen := map[string]bool{}
	for _, s := range scans {
		key := strings.ToLower(s.App)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// attachDetail fills in per-finding detail where credentials allow.
//
// Every failure here is a warning, never fatal. The report is already useful
// without it, and a lane that produces nothing because an API was slow is
// worse than one that produces counts.
func attachDetail(ctx context.Context, cfg config.Config, scans []appscan.ScanResult, since time.Time) {
	if cfg.QualysBaseURL == "" || cfg.QualysUsername == "" {
		logf("note   : no Qualys credentials configured - reporting counts only")
		return
	}
	api := qualys.NewAPI(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword)

	for i := range scans {
		if scans[i].Provider != "qualys-was" {
			continue
		}
		f, err := api.Findings(ctx, scans[i].App, since)
		if err != nil {
			logf("warn   : no detail for %s: %s",
				safelog.Line(scans[i].App), safelog.Line(err.Error()))
			continue
		}
		scans[i].Findings = f
	}
}

// shortSubject keeps a vendor subject to one readable line in a log.
//
// Subjects come from outside and reach a log that a person reads; safelog
// handles the injection problem, this handles the length.
func shortSubject(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return s
}
