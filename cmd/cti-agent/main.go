package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/cti"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/kev"
	"github.com/zany2dmax/cti-agent/internal/mailbox"
	"github.com/zany2dmax/cti-agent/internal/patchtuesday"
	"github.com/zany2dmax/cti-agent/internal/report"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/providers"
)

func main() {
	ctx := context.Background()

	// A catch-up window, for the morning after the lane was off.
	//
	// GRAPH_LOOKBACK_HOURS is the standing setting and stays that. This flag
	// exists because the alternative was editing the production credentials
	// file for a one-off run and remembering to put it back - and a forgotten
	// revert means every daily run silently re-reports a week of mail. It
	// also cannot be passed through the environment: the cti-agent wrapper
	// hops to the service account with a fixed --preserve-env list, so
	// `GRAPH_LOOKBACK_HOURS=168 sudo cti-agent ...` is stripped at the sudo
	// boundary and runs a 24-hour window while looking like it worked.
	lookback := flag.Duration("lookback", 0,
		"override GRAPH_LOOKBACK_HOURS for this run only, e.g. 168h to catch up "+
			"after the timer was off. The window used is always printed and "+
			"appears in the report header")
	flag.Parse()

	// fleet.env. run-digest sources it in shell before calling this, so under
	// systemd this is a no-op; `sudo cti-agent cti-agent` does not, and the
	// wrapper passes only the FLEET_* layout. Existing environment always
	// wins, so the runner's values are untouched.
	fleetenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %s", safelog.Line(err.Error()))
	}

	// Validated, not clamped. Silently reducing a window the operator asked
	// for would produce a report that covers less than its header claims.
	catchUp := *lookback > 0
	if catchUp {
		if err := config.ValidateLookback(*lookback); err != nil {
			log.Fatalf("--lookback: %s", safelog.Line(err.Error()))
		}
		log.Printf("CATCH-UP RUN: looking back %s instead of the configured %s. "+
			"Findings already reported in an earlier digest will appear again; "+
			"the enrich lane marks them as seen before.",
			*lookback, cfg.GraphLookback)
		cfg.GraphLookback = *lookback
	}

	since := time.Now().Add(-cfg.GraphLookback)

	graphClient := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	messages, err := graphClient.RecentMessages(ctx, cfg.GraphMailbox, cfg.GraphFolder, since)
	if err != nil {
		log.Fatalf("graph read failed: %s", safelog.Line(err.Error()))
	}

	// Count messages that actually carried a CVE separately from the total.
	// Reporting one number made "Emails inspected: 14" read as "14 emails
	// brought new CVE information", when it meant "14 emails arrived".
	cves := map[string]bool{}
	// trusted is the CVEs at least one trusted sender mentioned: a sender the
	// fleet reads (Qualys, or MAILBOX_FEED_SENDERS) whom Exchange Online
	// authenticated. Anyone can mail the mailbox a real CVE, and a critical
	// one present in the estate used to earn a Jira ticket on that alone
	// (PrimeSec attack vector 10786589). The ticket is still filed; cti-jira
	// labels one with no trusted source so a person can see it was not.
	trusted := map[string]bool{}
	feed := splitList(cfg.MailboxFeedSenders)
	withCVEs := 0
	selfSent := 0
	subjects := make([]report.ScannedEmail, 0, len(messages))
	seen := make([]mailbox.Processed, 0, len(messages))
	var skippedSubjects []string
	for _, msg := range messages {
		// Never read our own report back in.
		//
		// The digest is sent TO the mailbox the digest READS, so yesterday's
		// digest arrives as today's input and its CVEs are extracted and
		// presented as newly mentioned. That is self-sustaining: a CVE
		// reported once re-enters every subsequent run, so the daily can never
		// go quiet and "emails mentioning a CVE" is fiction.
		//
		// Nothing about it looked wrong. The email was well-formed, the CVE
		// was real, and every stage did exactly what it was written to do.
		// Observed 2026-10-04, where the single CVE-bearing email of the run
		// was the previous day's own Sev5 digest.
		//
		// Skipped before anything else so it cannot reach the extractor, the
		// counts, the subject list, or the processed ledger that decides what
		// the cleanup lane may archive.
		if msg.SelfSent {
			selfSent++
			continue
		}

		// A catalogue mail - Qualys's weekly "Latest Vulnerabilities Added to
		// the Knowledge Base" - names thousands of CVEs that say nothing about
		// our estate, and each one costs a live scanner lookup. On 2026-11-02
		// that was 5,292 lookups at 3.5 s against a one-hour limit, and the
		// daily sent nothing. Left out of the ledger too, so the cleanup lane
		// does not move it: other lanes may want that mail.
		if _, skip := cfg.SkipsSubject(msg.Subject); skip {
			skippedSubjects = append(skippedSubjects, safelog.Line(msg.Subject))
			continue
		}

		text := msg.Subject + "\n" + msg.BodyText
		found := cti.ExtractCVEs(text)
		if len(found) > 0 {
			withCVEs++
		}
		fromFeed := trustedSource(msg, feed)
		for _, cve := range found {
			cves[cve] = true
			if fromFeed {
				trusted[cve] = true
			}
		}
		subjects = append(subjects, report.ScannedEmail{
			Subject:  msg.Subject,
			Received: msg.ReceivedDateTime,
			HasCVE:   len(found) > 0,
		})
		// What the cleanup lane will later be allowed to act on. Recorded here
		// because this is the only place that knows a message was read AND
		// what was found in it; deriving either afterwards would be guessing.
		seen = append(seen, mailbox.Processed{
			ID:        msg.ID,
			Subject:   msg.Subject,
			Received:  msg.ReceivedDateTime,
			HasCVE:    len(found) > 0,
			AutoReply: msg.IsAutoReply(),
		})
	}

	// Say it out loud. A filter that silently removes input is how the next
	// four-day blind spot starts: if this number is ever larger than the
	// number of reports the fleet sent in the window, something legitimate is
	// being dropped and nobody would otherwise find out.
	if len(skippedSubjects) > 0 {
		log.Printf("skipped %d message(s) whose subject matches DIGEST_SKIP_SUBJECTS "+
			"(no CVEs read from them): %s", len(skippedSubjects), strings.Join(skippedSubjects, " | "))
	}
	if selfSent > 0 {
		log.Printf("skipped %d message(s) this fleet sent itself - "+
			"the digest is delivered to the mailbox it reads, and reading it "+
			"back would re-report its own CVEs every day", selfSent)
	}

	// Hold back what the monthly Patch Tuesday synopsis has already sent.
	//
	// A Patch Tuesday drops hundreds of Microsoft CVEs into the mailbox in one
	// afternoon. Repeated here they are hundreds of rows saying "Microsoft
	// released patches", which buries the two or three things the daily exists
	// to surface - and they are already in the monthly email, organised by the
	// update that fixes them, which is how somebody actually acts on them.
	//
	// Evidence, not a guess: only CVEs named in a manifest the monthly lane
	// marked SENT are held. No manifest, an unsent one, or an unreadable one
	// means everything is reported as before. The daily being noisy is a bad
	// day; the daily silently dropping CVEs that no other email carried is the
	// failure mode this whole codebase is built to avoid.
	//
	// This runs before the provider lookups, so a release's CVEs also stop
	// costing several hundred scanner calls a day for a fortnight.
	all := make([]string, 0, len(cves))
	for cve := range cves {
		all = append(all, cve)
	}
	sort.Slice(all, func(i, j int) bool { return cti.CVELess(all[i], all[j]) })

	manifests, err := patchtuesday.RecentManifests(os.Getenv("FLEET_HOME"), time.Now())
	if err != nil {
		// Loud, and then carry on with everything. An unreadable manifest must
		// not be able to decide anything.
		//
		// This is the message here that really does carry outside text: the
		// error embeds a path built from FLEET_HOME and a parse failure from
		// the manifest file's own contents. A newline in either forges a
		// second journal record, which journalctl renders looking exactly like
		// one this program wrote - in the journal an operator reads to find
		// out why a lane misbehaved. Hence safelog.Line(), which replaces
		// every control character and is tested in internal/safelog.
		//
		// #nosec G706 -- the control is safelog.Line() on the line below. G706 is
		// taint analysis and it does not model sanitisers: it tracks
		// os.Getenv("FLEET_HOME") to this call and stops there, so it reports
		// the flow whether or not anything scrubs the value in between. It
		// also does not flag the three log.Printf calls further down this
		// function, which carry a path and an error out of the same
		// environment through mailbox.LogPath() - identical exposure,
		// invisible to the rule because the os.Getenv sits behind a helper.
		// Those are sanitised too, on their own merits rather than because
		// anything demanded it: this finding marks where the os.Getenv call
		// is written, not whether a log record can be forged.
		//
		// If this annotation outlives the safelog.Line() call, the suppression
		// is wrong and nothing automated will say so. internal/safelog's own
		// tests prove the sanitiser works, so deleting the FUNCTION fails a
		// test - but deleting the CALL on the line below, and leaving this
		// comment, fails nothing. Said plainly rather than implied, because a
		// comment claiming more coverage than exists is how a suppression
		// outlives its justification.
		log.Printf("WARNING: Patch Tuesday manifest unreadable (%s); reporting "+
			"every CVE found, including any the monthly synopsis covers",
			safelog.Line(err.Error()))
	}
	// KEV is never held (decided 2026-11-11). The synopsis carries no tickets,
	// and the hold runs before the lookup, so a held CVE could never earn
	// one - including a Microsoft CVE CISA adds to KEV after the synopsis
	// went out. An unreadable catalog holds as before, and says so.
	onKEV, kerr := kev.LoadCatalog(os.Getenv("FLEET_HOME"))
	if kerr != nil {
		// #nosec G706 -- sanitised by safelog.Line(), as at the manifest warning
		// above, where the reasoning is set out in full. The error wraps the
		// catalog path under os.Getenv("FLEET_HOME"), so the taint is real and
		// the control is the scrub the rule cannot see. Remove this annotation
		// if the safelog.Line() call below is ever removed.
		log.Printf("WARNING: KEV catalog unreadable (%s); Patch Tuesday CVEs on "+
			"KEV are held with the rest today", safelog.Line(kerr.Error()))
	}
	keep, held := patchtuesday.HeldExcept(all, manifests, func(c string) bool { return onKEV[c] })
	if n := passedKEV(all, held, manifests, onKEV); n > 0 {
		log.Printf("reporting %d Patch Tuesday CVE(s) on CISA KEV despite the "+
			"synopsis: KEV is looked up and ticketed every day", n)
	}
	if len(held) > 0 {
		// #nosec G706 -- the taint analysis is right that `held` derives from a
		// file path read out of the environment, and wrong that anything
		// tainted reaches the log: the only values interpolated are len(held)
		// and len(keep). An int cannot carry a newline or a control character,
		// which is the whole of CWE-117. Not "fixed" by sanitising an integer,
		// which would be a control that looks like one and is not.
		log.Printf("holding back %d CVE(s) already sent in a Patch Tuesday "+
			"synopsis; %d remain", len(held), len(keep))
	}

	provider, err := buildLookupProvider(cfg)
	if err != nil {
		log.Fatalf("lookup provider config error: %s", safelog.Line(err.Error()))
	}

	results := make([]vulnlookup.Result, 0, len(keep))
	for _, cve := range keep {
		res, err := provider.LookupCVE(ctx, cve)
		if err != nil && res.Status == "" {
			res = vulnlookup.Result{CVE: cve, Source: provider.Name(), Status: vulnlookup.StatusUnknown, Reason: err.Error()}
		}
		results = append(results, res)
	}
	sort.Slice(results, func(i, j int) bool { return cti.CVELess(results[i].CVE, results[j].CVE) })

	scan := report.Scan{
		Messages:  len(messages),
		WithCVEs:  withCVEs,
		CVEsFound: len(cves),
		Subjects:  subjects,
		Held:      held,
		CatchUp:   catchUp,
		Lookback:  cfg.GraphLookback,
		Trusted:   trusted,
	}
	if err := report.WriteMarkdownScan(cfg.ReportPath, cfg.GraphMailbox, since, scan, provider.Name(), results); err != nil {
		// #nosec G706 -- sanitised by safelog.Line(), as at the manifest warning
		// above, where the reasoning is set out in full. The error wraps
		// cfg.ReportPath, which config.load() reads from REPORT_PATH, so the
		// taint is real and the control is the scrub the rule cannot see.
		//
		// This finding is one I caused: with `%v` on an error gosec said
		// nothing, and changing it to `%s` on a sanitised string is what made
		// the flow visible to it. Reverting to `%v` would silence the scanner
		// by removing the sanitiser - quieter output, worse code - so the
		// annotation stays and the scrub stays.
		log.Fatalf("write report failed: %s", safelog.Line(err.Error()))
	}

	// Record what was read, AFTER the report is on disk. The ordering is the
	// point: this log is the cleanup lane's authority to move mail, so it must
	// never claim a message was processed by a run that then failed to produce
	// anything. A failure to write the log is not fatal - losing today's
	// findings over a bookkeeping file would be worse - but it is loud,
	// because the consequence is that cleanup will leave everything alone and
	// otherwise look like it worked.
	if path := mailbox.LogPath(); path == "" {
		// Say it. This branch used to be an implicit no-op, and an implicit
		// no-op here is the whole failure this file keeps warning about: the
		// digest is the ONLY writer of the processed-message log, and that log
		// is the cleanup lane's only authority to move mail. With no
		// FLEET_HOME the digest wrote nothing, reported nothing, and
		// cti-mailbox then answered "The digest has read no mail today"
		// every single day - a refusal indistinguishable from a quiet mailbox,
		// forever, with both lanes exiting 0 and looking healthy.
		log.Printf("NOTE: neither FLEET_PROCESSED_LOG nor FLEET_HOME is set, so "+
			"no processed-message log was written. %d CVE(s) were still found "+
			"and reported; only mailbox cleanup is affected, and it will keep "+
			"refusing to touch the mailbox until this is set", len(cves))
	} else {
		store := mailbox.NewStore(path)
		l, err := store.Load()
		if err != nil {
			// safelog.Line() for the same reason as the manifest warning above:
			// this error carries a path from FLEET_PROCESSED_LOG or FLEET_HOME
			// and a parse failure from the file's contents. gosec does not
			// flag these two calls - the os.Getenv is behind
			// mailbox.LogPath(), where its taint analysis loses it - but the
			// exposure is identical, and sanitising only the line a scanner
			// happened to notice is how a codebase ends up with one defended
			// path and three undefended ones beside it.
			log.Printf("WARNING: processed-message log unreadable (%s); mailbox "+
				"cleanup will not move anything until this is fixed",
				safelog.Line(err.Error()))
		} else {
			store.Record(l, seen)
			if err := store.Save(l); err != nil {
				log.Printf("WARNING: could not write the processed-message log "+
					"(%s); mailbox cleanup will not move today's mail",
					safelog.Line(err.Error()))
			} else {
				// The path, not an error, and it comes from the same
				// environment. A forged record here would be a quiet success
				// message, which is the most useful kind to forge.
				log.Printf("recorded %d message(s) in %s", len(seen), safelog.Line(path))
			}
		}
	}
	log.Printf("scanned %d email(s) since %s; %d mentioned a CVE; %d distinct CVE(s)",
		scan.Messages, since.Format(time.RFC3339), scan.WithCVEs, scan.CVEsFound)

	// "No CVEs found" has to stay true. With suppression in the pipeline the
	// interesting case is a window where everything found was held back: that
	// is not a quiet day, it is a day whose news is in the monthly email, and
	// saying "no CVEs found" would be the reassuring-but-wrong sentence.
	switch {
	case len(cves) == 0:
		fmt.Printf("No CVEs found. Wrote %s\n", cfg.ReportPath)
	case len(keep) == 0:
		fmt.Printf("All %d CVE(s) found were held for the monthly Patch Tuesday "+
			"synopsis, which has already been sent. Wrote %s\n",
			len(held), cfg.ReportPath)
	default:
		fmt.Printf("Wrote %s\n", cfg.ReportPath)
	}
}

func buildLookupProvider(cfg config.Config) (vulnlookup.LookupProvider, error) {
	return providers.Build(cfg)
}

// splitList splits a comma-separated setting, dropping blanks.
func splitList(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// trustedSource reports a message from a sender the fleet reads (Qualys, or
// MAILBOX_FEED_SENDERS) whom the receiving server authenticated. Both: an
// allowlisted From can be forged, and an authenticated sender can be anyone
// with a domain of their own.
func trustedSource(msg graph.Message, feed []string) bool {
	if !mailbox.FleetSender(msg.From, feed) {
		return false
	}
	ok, _ := msg.VouchedFor()
	return ok
}

// passedKEV counts the CVEs a sent synopsis covered that were reported anyway
// because they are on KEV, for the log line.
func passedKEV(all []string, held map[string]string, manifests []patchtuesday.Manifest, onKEV map[string]bool) int {
	if len(onKEV) == 0 {
		return 0
	}
	_, wouldHold := patchtuesday.Held(all, manifests)
	n := 0
	for c := range wouldHold {
		if _, still := held[c]; !still {
			n++
		}
	}
	return n
}
