package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/qualys"
)

type CVEResult struct {
	CVE        string
	QIDs       []int
	Status     string
	HostCount  int
	MaxQDS     int
	LastSeen   string
	SampleHosts []string
	Reason     string
}

func WriteMarkdown(path string, mailbox string, since time.Time, emailCount int, results []CVEResult) error {
	sort.Slice(results, func(i, j int) bool { return results[i].CVE < results[j].CVE })

	var b strings.Builder
	b.WriteString("# CTI / CVE / Qualys Daily Report\n\n")
	b.WriteString(fmt.Sprintf("- Mailbox: `%s`\n", mailbox))
	b.WriteString(fmt.Sprintf("- Lookback since: `%s`\n", since.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Emails inspected: `%d`\n", emailCount))
	b.WriteString(fmt.Sprintf("- Generated: `%s`\n\n", time.Now().Format(time.RFC3339)))

	b.WriteString("| CVE | Status | QIDs | Host Count | Max QDS | Last Seen | Sample Hosts / Reason |\n")
	b.WriteString("|---|---|---:|---:|---:|---|---|\n")
	for _, r := range results {
		sample := r.Reason
		if len(r.SampleHosts) > 0 {
			sample = strings.Join(r.SampleHosts, ", ")
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d | %s | %s |\n",
			r.CVE,
			r.Status,
			ints(r.QIDs),
			r.HostCount,
			r.MaxQDS,
			r.LastSeen,
			escape(sample),
		))
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func FromDetections(cve string, qids []int, detections map[int]qualys.DetectionSummary) CVEResult {
	res := CVEResult{CVE: cve, QIDs: qids, Status: "NOT_PRESENT"}
	for _, qid := range qids {
		if d, ok := detections[qid]; ok && d.HostCount > 0 {
			res.Status = "PRESENT"
			res.HostCount += d.HostCount
			if d.MaxQDS > res.MaxQDS {
				res.MaxQDS = d.MaxQDS
			}
			if d.LastSeen > res.LastSeen {
				res.LastSeen = d.LastSeen
			}
			res.SampleHosts = append(res.SampleHosts, d.Hosts...)
		}
	}
	return res
}

func ints(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ",")
}

func escape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
