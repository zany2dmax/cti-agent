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
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
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
	authFailOut := flag.String("auth-fail-out", "",
		"write one line per scan whose configured credential failed to "+
			"authenticate; the runner alerts the operator when this file is "+
			"non-empty. Absent or empty means every credential worked.")
	flag.Parse()

	// fleet.env, so a run by hand gets the same settings systemd gives it.
	// Existing environment always wins.
	//
	// Every other command that reads credentials does this, and this one did
	// not. That - not the runner - was the real cause of "missing required
	// environment variables: CLIENT_ID CLIENT_SECRET GRAPH_MAILBOX TENANT_ID"
	// on a box where all four were set. Making run-appscan source the file
	// fixed the timer path and left `sudo cti-agent cti-appscan ...` broken,
	// which is the path anyone takes to run a one-off.
	fleetenv.Load()

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

	// The API is optional by construction. The counts come from the
	// notification emails and need no credentials, so the API being down,
	// rate-limited or unlicensed costs identity, the email-less scans and the
	// per-finding detail - and not the report.
	windowStart := time.Now().Add(-*since)
	if !*noDetail {
		if api := wasAPI(cfg); api != nil {
			scans = reconcile(ctx, api, scans, windowStart, qualys.PortalOrigin(cfg.QualysBaseURL))
			scans = newestPerApp(scans)
			attachDetail(ctx, api, scans, windowStart)
		} else {
			scans = newestPerApp(scans)
		}
	} else {
		scans = newestPerApp(scans)
	}

	// The only hosts a link may be clickable for. Registered here rather than
	// inside internal/appscan, which is vendor-neutral; forgetting it degrades
	// every link to plain text rather than dropping one or opening the gate.
	appscan.AllowPortalHosts(qualys.Provider{}.Name(), qualys.PortalHosts...)

	block := appscan.Render(scans, time.Now())

	if *subjectOnly {
		fmt.Println(block.Subject)
		return exitOK
	}

	// THE AUTHENTICATION-FAILURE FILE, AND WHY IT IS A FILE.
	//
	// A credential that was configured and did not work is the fleet
	// operator's problem, not the App Dev audience's: nobody writing
	// application code can fix a scanner login. So it has to reach a different
	// person from the one this report is addressed to.
	//
	// This binary does not send mail and must not learn how - cti-mailer holds
	// the only recipient gate in the fleet, and cti-alert is the only
	// escalation channel. So the finding is written to a file and the runner,
	// which already knows how to call cti-alert, decides. Same shape as the
	// cve->ticket map the digest passes to brief.py, and for the same reason:
	// the component that can talk to the outside world is the one that talks.
	//
	// Empty file, or no file, means no failures. The runner must not treat a
	// missing file as an error, because the overwhelmingly common case is that
	// every credential worked.
	if *authFailOut != "" {
		if err := writeAuthFailures(*authFailOut, scans); err != nil {
			// A warning. The report is the deliverable; losing the alert hint
			// must not cost the weekly mail.
			logf("warn   : could not write %s: %s",
				safelog.Line(*authFailOut), safelog.Line(err.Error()))
		}
	}
	for _, s := range scans {
		if s.Auth.Failed() {
			logf("AUTH FAILED: %s (%s) - the fleet operator needs to know; "+
				"this scan covered less than it was configured to cover",
				safelog.Line(s.App), safelog.Line(s.Auth.Status))
		}
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

// writeAuthFailures records the scans whose credential did not work.
//
// Always written, even when empty. A file that exists and is empty says "this
// run checked and found none"; an absent file says "this run did not check",
// and the runner cannot tell those apart if the empty case is skipped. That
// distinction is the whole value of the file - a lane that quietly stops
// reporting failures looks exactly like a lane with no failures, which is the
// mistake this fleet has made more than once.
//
// 0600 and one line per application, no counts: it names which applications
// exist and which of them has a broken scanner credential, which is the same
// class of information as the report itself.
func writeAuthFailures(path string, scans []appscan.ScanResult) error {
	var b strings.Builder
	for _, s := range scans {
		if !s.Auth.Failed() {
			continue
		}
		status := s.Auth.Status
		if status == "" {
			status = "no authentication status in the notification"
		}
		// Tab-separated and sanitised. The runner puts this in a --reason
		// argument that reaches an email and a journal, and both fields come
		// from a vendor email.
		fmt.Fprintf(&b, "%s\t%s\t%s\n",
			safelog.Line(s.App), safelog.Line(s.Auth.Record), safelog.Line(status))
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
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

	// NOT deduplicated per application here. That happens after
	// reconciliation, when each result can be keyed on the scanner's own
	// application id rather than a name derived from the scan title.
	return scans, problems
}

// newestPerApp keeps one scan per application: the newest. An application
// scanned twice in a week would otherwise appear twice with different
// numbers, and a reader has no way to tell which is current.
//
// Keyed on the scanner's application id when reconciliation supplied one,
// and on the whitespace-collapsed lower-cased name otherwise. Real names carry
// trailing and doubled spaces, which made one application two.
func newestPerApp(scans []appscan.ScanResult) []appscan.ScanResult {
	when := func(s appscan.ScanResult) time.Time {
		if !s.Finished.IsZero() {
			return s.Finished
		}
		return s.Started
	}
	sort.SliceStable(scans, func(i, j int) bool {
		return when(scans[i]).After(when(scans[j]))
	})
	var out []appscan.ScanResult
	seen := map[string]bool{}
	for _, s := range scans {
		key := "id:" + s.AppID
		if s.AppID == "" {
			key = "name:" + strings.ToLower(strings.Join(strings.Fields(s.App), " "))
		}
		if s.AppID == "" && strings.TrimSpace(s.App) == "" {
			key = ""
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// wasAPI is the Qualys WAS client, or nil when no credentials are set.
func wasAPI(cfg config.Config) *qualys.API {
	if cfg.QualysBaseURL == "" || cfg.QualysUsername == "" {
		logf("note   : no Qualys credentials configured - reporting counts from the notifications only")
		return nil
	}
	return qualys.NewAPI(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword)
}

// reconcile joins the notifications to the WAS scan list.
//
// A failure is a warning and the email-only results go on unchanged: the
// counts are in the notifications, and losing the scan list costs the real
// application names, the email-less scans and the id-keyed detail lookup.
func reconcile(ctx context.Context, api *qualys.API, scans []appscan.ScanResult, since time.Time, portal string) []appscan.ScanResult {
	list, err := api.Scans(ctx, since.Add(-qualys.ScanMargin))
	if err != nil {
		logf("warn   : WAS scan list unavailable, reporting from the notifications only: %s",
			safelog.Line(err.Error()))
		return scans
	}
	if portal == "" {
		logf("note   : QUALYS_BASE_URL does not map to a known Qualys UI host, so " +
			"report links stay plain text from the notifications")
	}
	out, rec := qualys.Reconcile(scans, list, since, portal)
	added := len(out) - len(scans)
	logf("scans  : %d in the WAS scan list, %d matched a notification, %d added "+
		"with no notification, %d skipped (discovery, in flight, or on-demand faults)",
		len(list), rec.Matched, added, rec.Skipped)
	for _, ref := range rec.Unmatched {
		// The reference is a scanner identifier, not text from the mail body.
		logf("warn   : notification for %s has no match in the WAS scan list - "+
			"its counts are kept; it was probably launched before the list window",
			safelog.Line(ref))
	}
	return out
}

// attachDetail fills in per-finding detail.
//
// Every failure here is a warning, never fatal. The report is already useful
// without it, and a lane that produces nothing because an API was slow is
// worse than one that produces counts.
func attachDetail(ctx context.Context, api *qualys.API, scans []appscan.ScanResult, since time.Time) {
	for i := range scans {
		// No detail for a scan we have no notification for: there are no
		// counts to explain, and an empty findings list would read as "none".
		if scans[i].Provider != "qualys-was" || scans[i].NoNotification {
			continue
		}
		if scans[i].AppID == "" {
			logf("note   : %s has no application id (no scan-list match), so detail "+
				"is looked up by a name derived from the scan title and may come back empty",
				safelog.Line(scans[i].App))
		}
		f, err := api.Findings(ctx, scans[i], since)
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
