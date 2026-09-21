package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/cti"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/mailbox"
	"github.com/zany2dmax/cti-agent/internal/patchtuesday"
	"github.com/zany2dmax/cti-agent/internal/report"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/crowdstrike"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/noop"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/qualys"
)

func main() {
	ctx := context.Background()

	// fleet.env. run-digest sources it in shell before calling this, so under
	// systemd this is a no-op; `sudo cti-agent cti-agent` does not, and the
	// wrapper passes only the FLEET_* layout. Existing environment always
	// wins, so the runner's values are untouched.
	fleetenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %s", oneLine(err.Error()))
	}

	since := time.Now().Add(-cfg.GraphLookback)

	graphClient := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	messages, err := graphClient.RecentMessages(ctx, cfg.GraphMailbox, cfg.GraphFolder, since)
	if err != nil {
		log.Fatalf("graph read failed: %s", oneLine(err.Error()))
	}

	// Count messages that actually carried a CVE separately from the total.
	// Reporting one number made "Emails inspected: 14" read as "14 emails
	// brought new CVE information", when it meant "14 emails arrived".
	cves := map[string]bool{}
	withCVEs := 0
	subjects := make([]report.ScannedEmail, 0, len(messages))
	seen := make([]mailbox.Processed, 0, len(messages))
	for _, msg := range messages {
		text := msg.Subject + "\n" + msg.BodyText
		found := cti.ExtractCVEs(text)
		if len(found) > 0 {
			withCVEs++
		}
		for _, cve := range found {
			cves[cve] = true
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
		// out why a lane misbehaved. Hence oneLine(), which replaces every
		// control character and is tested in main_test.go.
		//
		// #nosec G706 -- the control is oneLine() on the line below. G706 is
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
		// If this annotation outlives the oneLine() call, the suppression is
		// wrong and nothing automated will say so.
		// TestOneLineCannotBeUsedToForgeAJournalRecord proves the sanitiser
		// works, so deleting the FUNCTION fails a test - but deleting the
		// CALL on the line below, and leaving this comment, fails nothing.
		// Said plainly rather than implied, because a comment claiming more
		// coverage than exists is how a suppression outlives its
		// justification.
		log.Printf("WARNING: Patch Tuesday manifest unreadable (%s); reporting "+
			"every CVE found, including any the monthly synopsis covers",
			oneLine(err.Error()))
	}
	keep, held := patchtuesday.Held(all, manifests)
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
		log.Fatalf("lookup provider config error: %s", oneLine(err.Error()))
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
	}
	if err := report.WriteMarkdownScan(cfg.ReportPath, cfg.GraphMailbox, since, scan, provider.Name(), results); err != nil {
		// #nosec G706 -- sanitised by oneLine(), as at the manifest warning
		// above, where the reasoning is set out in full. The error wraps
		// cfg.ReportPath, which config.load() reads from REPORT_PATH, so the
		// taint is real and the control is the scrub the rule cannot see.
		//
		// This finding is one I caused: with `%v` on an error gosec said
		// nothing, and changing it to `%s` on a sanitised string is what made
		// the flow visible to it. Reverting to `%v` would silence the scanner
		// by removing the sanitiser - quieter output, worse code - so the
		// annotation stays and the scrub stays.
		log.Fatalf("write report failed: %s", oneLine(err.Error()))
	}

	// Record what was read, AFTER the report is on disk. The ordering is the
	// point: this log is the cleanup lane's authority to move mail, so it must
	// never claim a message was processed by a run that then failed to produce
	// anything. A failure to write the log is not fatal - losing today's
	// findings over a bookkeeping file would be worse - but it is loud,
	// because the consequence is that cleanup will leave everything alone and
	// otherwise look like it worked.
	if path := mailbox.LogPath(); path != "" {
		store := mailbox.NewStore(path)
		l, err := store.Load()
		if err != nil {
			// oneLine() for the same reason as the manifest warning above:
			// this error carries a path from FLEET_PROCESSED_LOG or FLEET_HOME
			// and a parse failure from the file's contents. gosec does not
			// flag these two calls - the os.Getenv is behind
			// mailbox.LogPath(), where its taint analysis loses it - but the
			// exposure is identical, and sanitising only the line a scanner
			// happened to notice is how a codebase ends up with one defended
			// path and three undefended ones beside it.
			log.Printf("WARNING: processed-message log unreadable (%s); mailbox "+
				"cleanup will not move anything until this is fixed",
				oneLine(err.Error()))
		} else {
			store.Record(l, seen)
			if err := store.Save(l); err != nil {
				log.Printf("WARNING: could not write the processed-message log "+
					"(%s); mailbox cleanup will not move today's mail",
					oneLine(err.Error()))
			} else {
				// The path, not an error, and it comes from the same
				// environment. A forged record here would be a quiet success
				// message, which is the most useful kind to forge.
				log.Printf("recorded %d message(s) in %s", len(seen), oneLine(path))
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

// oneLine makes a string safe to put in a log record.
//
// A log line is a record, and a record that can contain a newline is a record
// anyone who can influence the text can forge. journalctl shows the forged
// line looking exactly like one this program wrote, which makes the journal
// useless for the one job it has here: telling an operator what actually
// happened. Tabs and other control characters go too - they let text be
// pushed off the visible width of a terminal.
//
// Replaces rather than strips, so the mangling is visible: a message that
// arrived with newlines in it should look odd, not look clean.
func oneLine(s string) string {
	const maxLogged = 300 // an error, not a file
	// IsControl covers it: newline, carriage return and tab are all C0
	// controls, so listing them separately would just be three redundant
	// comparisons in front of the check that actually decides.
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	// Runes, not bytes. A byte-offset cut lands in the middle of a multi-byte
	// character often enough, and then the control meant to make the log
	// readable is the thing that put invalid UTF-8 in it.
	if r := []rune(out); len(r) > maxLogged {
		return string(r[:maxLogged]) + "... (truncated)"
	}
	return out
}

func buildLookupProvider(cfg config.Config) (vulnlookup.LookupProvider, error) {
	switch cfg.LookupProvider {
	case "qualys":
		return qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword, cfg.QualysKBCachePath, cfg.QualysKBMaxAge), nil
	case "crowdstrike":
		return crowdstrike.New(), nil
	case "none", "noop", "":
		return noop.New(), nil
	default:
		return nil, fmt.Errorf("unsupported LOOKUP_PROVIDER %q", cfg.LookupProvider)
	}
}
