package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
)

func WriteMarkdown(path string, mailbox string, since time.Time, emailCount int, provider string, results []vulnlookup.Result) error {
	var b strings.Builder
	b.WriteString("# CTI / CVE Daily Report\n\n")
	fmt.Fprintf(&b, "- Mailbox: `%s`\n", mailbox)
	fmt.Fprintf(&b, "- Lookback since: `%s`\n", since.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Emails inspected: `%d`\n", emailCount)
	fmt.Fprintf(&b, "- Lookup provider: `%s`\n", provider)
	fmt.Fprintf(&b, "- Generated: `%s`\n\n", time.Now().Format(time.RFC3339))

	b.WriteString("| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts / Reason |\n")
	b.WriteString("|---|---|---|---|---:|---:|---|---|\n")
	for _, r := range results {
		sample := r.Reason
		if len(r.SampleHosts) > 0 {
			sample = strings.Join(r.SampleHosts, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d | %s | %s |\n",
			r.CVE,
			r.Status,
			r.Source,
			strings.Join(r.ExternalIDs, ","),
			r.HostCount,
			r.MaxScore,
			r.LastSeen,
			escape(sample),
		)
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func escape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
