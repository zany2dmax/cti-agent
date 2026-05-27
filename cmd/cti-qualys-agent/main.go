package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/config"
	"github.com/yourorg/cti-qualys-agent/internal/cti"
	"github.com/yourorg/cti-qualys-agent/internal/graph"
	"github.com/yourorg/cti-qualys-agent/internal/qualys"
	"github.com/yourorg/cti-qualys-agent/internal/report"
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

	if len(cves) == 0 {
		if err := report.WriteMarkdown(cfg.ReportPath, cfg.GraphMailbox, since, len(messages), nil); err != nil {
			log.Fatalf("write report failed: %v", err)
		}
		fmt.Printf("No CVEs found. Wrote %s\n", cfg.ReportPath)
		return
	}

	qualysClient := qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword)
	kb, err := qualysClient.LoadOrBuildKBCache(ctx, cfg.QualysKBCachePath)
	if err != nil {
		log.Fatalf("qualys KB cache failed: %v", err)
	}

	var results []report.CVEResult
	for cve := range cves {
		qids := kb[strings.ToUpper(cve)]
		if len(qids) == 0 {
			results = append(results, report.CVEResult{
				CVE:    cve,
				Status: "UNKNOWN",
				Reason: "No Qualys KnowledgeBase CVE-to-QID mapping found",
			})
			continue
		}

		detections, err := qualysClient.HostDetections(ctx, qids)
		if err != nil {
			results = append(results, report.CVEResult{
				CVE:    cve,
				QIDs:   qids,
				Status: "UNKNOWN",
				Reason: fmt.Sprintf("Qualys detection lookup failed: %v", err),
			})
			continue
		}
		results = append(results, report.FromDetections(cve, qids, detections))
	}

	if err := report.WriteMarkdown(cfg.ReportPath, cfg.GraphMailbox, since, len(messages), results); err != nil {
		log.Fatalf("write report failed: %v", err)
	}
	fmt.Printf("Wrote %s\n", cfg.ReportPath)
}
