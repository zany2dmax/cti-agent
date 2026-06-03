package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/config"
	"github.com/yourorg/cti-qualys-agent/internal/cti"
	"github.com/yourorg/cti-qualys-agent/internal/graph"
	"github.com/yourorg/cti-qualys-agent/internal/report"
	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup/crowdstrike"
	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup/qualys"
)

func main() {
	ctx := context.Background()
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

	cves := map[string]bool{}
	for _, msg := range messages {
		text := msg.Subject + "\n" + msg.BodyText
		for _, cve := range cti.ExtractCVEs(text) {
			cves[cve] = true
		}
	}

	provider, err := buildLookupProvider(cfg)
	if err != nil {
		log.Fatalf("lookup provider config error: %v", err)
	}

	results := make([]vulnlookup.Result, 0, len(cves))
	for cve := range cves {
		res, err := provider.LookupCVE(ctx, cve)
		if err != nil && res.Status == "" {
			res = vulnlookup.Result{CVE: cve, Source: provider.Name(), Status: vulnlookup.StatusUnknown, Reason: err.Error()}
		}
		results = append(results, res)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].CVE < results[j].CVE })

	if err := report.WriteMarkdown(cfg.ReportPath, cfg.GraphMailbox, since, len(messages), provider.Name(), results); err != nil {
		log.Fatalf("write report failed: %v", err)
	}

	if len(cves) == 0 {
		fmt.Printf("No CVEs found. Wrote %s\n", cfg.ReportPath)
		return
	}
	fmt.Printf("Wrote %s\n", cfg.ReportPath)
}

func buildLookupProvider(cfg config.Config) (vulnlookup.LookupProvider, error) {
	switch cfg.LookupProvider {
	case "qualys":
		return qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword, cfg.QualysKBCachePath), nil
	case "crowdstrike":
		return crowdstrike.New(), nil
	default:
		return nil, fmt.Errorf("unsupported LOOKUP_PROVIDER %q", cfg.LookupProvider)
	}
}
