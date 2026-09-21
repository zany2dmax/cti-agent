package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

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
		log.Fatalf("config error: %v", err)
	}

	since := time.Now().Add(-cfg.GraphLookback)

	graphClient := graph.New(cfg.TenantID, cfg.ClientID, cfg.ClientSecret)
	messages, err := graphClient.RecentMessages(ctx, cfg.GraphMailbox, cfg.GraphFolder, since)
	if err != nil {
		log.Fatalf("graph read failed: %v", err)
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
		log.Printf("WARNING: Patch Tuesday manifest unreadable (%v); reporting "+
			"every CVE found, including any the monthly synopsis covers", err)
	}
	keep, held := patchtuesday.Held(all, manifests)
	if len(held) > 0 {
		log.Printf("holding back %d CVE(s) already sent in a Patch Tuesday "+
			"synopsis; %d remain", len(held), len(keep))
	}

	provider, err := buildLookupProvider(cfg)
	if err != nil {
		log.Fatalf("lookup provider config error: %v", err)
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
		log.Fatalf("write report failed: %v", err)
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
			log.Printf("WARNING: processed-message log unreadable (%v); mailbox "+
				"cleanup will not move anything until this is fixed", err)
		} else {
			store.Record(l, seen)
			if err := store.Save(l); err != nil {
				log.Printf("WARNING: could not write the processed-message log "+
					"(%v); mailbox cleanup will not move today's mail", err)
			} else {
				log.Printf("recorded %d message(s) in %s", len(seen), path)
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
