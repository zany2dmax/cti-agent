package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
)

// Hostname disclosure mode, from REPORT_HOSTNAMES.
//
// A CTI report pairs "this CVE is exploitable" with "these are the machines
// that have it", which makes it a targeting list. Reports have been committed
// to this repository before, so the default is to redact and callers must opt
// in to real hostnames.
const (
	hostsRedact = "redact" // default: stable pseudonyms
	hostsCount  = "count"  // host count only, no per-host rows
	hostsFull   = "full"   // real hostnames - opt in deliberately
)

func hostMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("REPORT_HOSTNAMES"))) {
	case hostsFull:
		return hostsFull
	case hostsCount:
		return hostsCount
	default:
		return hostsRedact
	}
}

// pseudonym maps a hostname to a stable, non-reversible label so the same
// machine is recognizable across reports without naming it.
//
// REPORT_REDACTION_SALT should be set to a private value and kept stable.
// Without it, anyone holding a candidate list of your hostnames can confirm
// matches by hashing them - the mapping is deterministic, not secret.
func pseudonym(host, salt string) string {
	h := sha256.Sum256([]byte(salt + "\x00" + strings.ToLower(strings.TrimSpace(host))))
	return "host-" + hex.EncodeToString(h[:])[:8]
}

func redactHosts(hosts []string, mode, salt string) string {
	if len(hosts) == 0 {
		return ""
	}
	switch mode {
	case hostsFull:
		return strings.Join(hosts, ", ")
	case hostsCount:
		return fmt.Sprintf("%d host(s) - names withheld", len(hosts))
	default:
		out := make([]string, 0, len(hosts))
		seen := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			p := pseudonym(h, salt)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		return strings.Join(out, ", ")
	}
}

func WriteMarkdown(path string, mailbox string, since time.Time, emailCount int, provider string, results []vulnlookup.Result) error {
	mode := hostMode()
	salt := os.Getenv("REPORT_REDACTION_SALT")

	var b strings.Builder
	b.WriteString("# CTI / CVE Daily Report\n\n")
	fmt.Fprintf(&b, "- Mailbox: `%s`\n", mailbox)
	fmt.Fprintf(&b, "- Lookback since: `%s`\n", since.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Emails inspected: `%d`\n", emailCount)
	fmt.Fprintf(&b, "- Lookup provider: `%s`\n", provider)
	fmt.Fprintf(&b, "- Generated: `%s`\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Hostname disclosure: `%s`\n\n", mode)

	switch mode {
	case hostsFull:
		b.WriteString("> **Contains real hostnames.** This file maps exploitable CVEs to\n")
		b.WriteString("> specific machines. Do not commit it, attach it to anything public,\n")
		b.WriteString("> or store it outside controlled locations.\n\n")
	case hostsRedact:
		if salt == "" {
			b.WriteString("> Hostnames are pseudonymized without a salt, so the mapping is\n")
			b.WriteString("> confirmable by anyone holding a list of candidate hostnames. Set\n")
			b.WriteString("> `REPORT_REDACTION_SALT` to a private, stable value.\n\n")
		}
	}

	b.WriteString("| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts / Reason |\n")
	b.WriteString("|---|---|---|---|---:|---:|---|---|\n")
	for _, r := range results {
		sample := r.Reason
		if len(r.SampleHosts) > 0 {
			sample = redactHosts(r.SampleHosts, mode, salt)
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

	// 0600, not 0644 - this file is sensitive even when redacted, because the
	// CVE/host-count pairs alone describe where the environment is weak.
	return os.WriteFile(path, []byte(b.String()), 0600)
}

func escape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
