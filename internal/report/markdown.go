package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
)

// Hostname disclosure mode, from REPORT_HOSTNAMES.
//
// A CTI report pairs "this CVE is exploitable" with "these are the machines
// that have it", which makes it a targeting list if it leaks.
//
// The default is nonetheless "full", because the alternative is worse in
// practice: a pseudonym cannot be looked up in the scanner, so a redacted
// report tells you a Sev5 exists without telling you where, and the reader has
// to rerun the pipeline to act on it. An unactionable security report is not a
// safe security report.
//
// What keeps that defensible is everything around it: reports are written
// 0600, excluded by .gitignore, and mailed only to an allowlisted internal
// distribution list. Use "redact" or "count" for anything leaving that path.
const (
	hostsRedact = "redact" // stable pseudonyms, non-reversible
	hostsCount  = "count"  // host count only, no per-host rows
	hostsFull   = "full"   // default: real hostnames
)

func hostMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("REPORT_HOSTNAMES"))) {
	case hostsRedact:
		return hostsRedact
	case hostsCount:
		return hostsCount
	default:
		return hostsFull
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

// Scan describes what the mailbox pass actually did. It exists because the
// report used to print a single "Emails inspected: 14", which readers
// reasonably took to mean fourteen emails carried new CVE information. It
// meant neither: it was every message in the lookback window, whether or not
// it mentioned a CVE, and the window is purely time-based so the same messages
// are re-read on every run.
//
// Three numbers instead of one, because the difference between them is the
// interesting part - 40 emails yielding 2 CVEs and 3 emails yielding 21 are
// very different days.
type Scan struct {
	Messages  int  // every message Graph returned in the window
	WithCVEs  int  // how many of those actually mentioned a CVE
	CVEsFound int  // distinct CVE IDs extracted
	Truncated bool // set if the provider capped results (should not happen; we paginate)

	// Subjects is what was actually read, newest first. The digest lists these
	// so "N emails" can be checked rather than taken on trust - the single
	// count invited the question "which fourteen?" and could not answer it.
	Subjects []ScannedEmail

	// Held maps a CVE withheld from this report to the month whose Patch
	// Tuesday synopsis already covered it.
	//
	// Withheld from the TABLE, listed in full below it. The whole reason to
	// hold a Patch Tuesday release back from the daily is that a few hundred
	// rows about one vendor's monthly update drown everything else - but a
	// CVE that was suppressed and not written down anywhere is a CVE the
	// audit trail lost. The list is not in the `| CVE-` table format, so the
	// enrich lane and the row count in run-digest ignore it, and a human
	// reading the attachment can still see every ID.
	Held map[string]string
}

// ScannedEmail is one message the pass looked at.
type ScannedEmail struct {
	Subject  string
	Received time.Time
	HasCVE   bool
}

// Compat wrapper for callers that only have a message count.
func WriteMarkdown(path string, mailbox string, since time.Time, emailCount int, provider string, results []vulnlookup.Result) error {
	return WriteMarkdownScan(path, mailbox, since,
		Scan{Messages: emailCount, CVEsFound: len(results)}, provider, results)
}

func WriteMarkdownScan(path string, mailbox string, since time.Time, scan Scan, provider string, results []vulnlookup.Result) error {
	mode := hostMode()
	salt := os.Getenv("REPORT_REDACTION_SALT")

	var b strings.Builder
	b.WriteString("# CTI / CVE Daily Report\n\n")
	fmt.Fprintf(&b, "- Mailbox: `%s`\n", mailbox)
	fmt.Fprintf(&b, "- Lookback since: `%s`\n", since.Format(time.RFC3339))
	// Label each number for what it is. "Emails inspected" alone invited the
	// reading that all of them carried CVEs, and that every run saw fresh mail.
	fmt.Fprintf(&b, "- Emails in window: `%d` (all mail received since the lookback time)\n",
		scan.Messages)
	fmt.Fprintf(&b, "- Emails mentioning a CVE: `%d`\n", scan.WithCVEs)
	fmt.Fprintf(&b, "- Distinct CVEs extracted: `%d`\n", scan.CVEsFound)
	// Three numbers that add up, printed next to each other. Held CVEs were
	// extracted and then deliberately left out of the table, and a reader who
	// cannot reconcile "extracted 361" with a 9-row table will assume the
	// extraction is broken.
	if n := len(scan.Held); n > 0 {
		fmt.Fprintf(&b,
			"- Held for the monthly Patch Tuesday synopsis: `%d` (listed below, not in the table)\n", n)
		fmt.Fprintf(&b, "- Looked up and reported in the table: `%d`\n", len(results))
	}
	fmt.Fprintf(&b, "- Lookup provider: `%s`\n", provider)
	fmt.Fprintf(&b, "- Generated: `%s`\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Hostname disclosure: `%s`\n\n", mode)

	// Say plainly that this is a window, not a novelty feed. Whether a CVE is
	// new is decided downstream against first_seen in the findings database;
	// this pass has no memory and cannot know.
	b.WriteString("> The lookback is a time window, so a CVE that is still being\n")
	b.WriteString("> discussed appears in every run until it falls out of the window.\n")
	b.WriteString("> \"New since last run\" is determined by the enrich lane against\n")
	b.WriteString("> `first_seen` in the findings database, not here.\n\n")

	switch mode {
	case hostsFull:
		b.WriteString("> **Contains real hostnames.** This file maps exploitable CVEs to\n")
		b.WriteString("> specific machines - it is a targeting list. Do not commit it, attach\n")
		b.WriteString("> it to anything public, or store it outside controlled locations.\n")
		b.WriteString("> Set `REPORT_HOSTNAMES=redact` for a shareable copy.\n\n")
	case hostsRedact:
		if salt == "" {
			b.WriteString("> Hostnames are pseudonymized without a salt, so the mapping is\n")
			b.WriteString("> confirmable by anyone holding a list of candidate hostnames. Set\n")
			b.WriteString("> `REPORT_REDACTION_SALT` to a private, stable value.\n\n")
		}
	}

	// Hosts and Reason are SEPARATE columns. They used to share one, which
	// meant a diagnostic sentence ("No Qualys KnowledgeBase CVE-to-QID mapping
	// found") landed in the hosts field and got rendered downstream as though
	// it were a machine name.
	b.WriteString("| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts | Reason |\n")
	b.WriteString("|---|---|---|---|---:|---:|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d | %s | %s | %s |\n",
			r.CVE,
			r.Status,
			r.Source,
			strings.Join(r.ExternalIDs, ","),
			r.HostCount,
			r.MaxScore,
			r.LastSeen,
			escape(redactHosts(r.SampleHosts, mode, salt)),
			escape(r.Reason),
		)
	}

	// The held CVEs, in full, outside the table. Suppression that leaves no
	// record is indistinguishable from a parser that missed them.
	if len(scan.Held) > 0 {
		byMonth := map[string][]string{}
		for cve, month := range scan.Held {
			byMonth[month] = append(byMonth[month], cve)
		}
		months := make([]string, 0, len(byMonth))
		for m := range byMonth {
			months = append(months, m)
		}
		sort.Strings(months)

		fmt.Fprintf(&b,
			"\n## Held for the monthly Patch Tuesday synopsis (%d)\n\n", len(scan.Held))
		b.WriteString("These were extracted from this window's mail and deliberately kept\n")
		b.WriteString("out of the table above: the monthly synopsis for the month shown has\n")
		b.WriteString("already been sent, and it organises them by the update that fixes\n")
		b.WriteString("them. They were not looked up against the scanner here. Listed in\n")
		b.WriteString("full so nothing is suppressed without a record.\n")
		for _, m := range months {
			list := byMonth[m]
			sort.Strings(list)
			fmt.Fprintf(&b, "\n**%s** (%d):\n\n", m, len(list))
			for _, cve := range list {
				fmt.Fprintf(&b, "- %s\n", cve)
			}
		}
		b.WriteString("\n")
	}

	// What was actually read. A single "14 emails" count invites the question
	// "which fourteen?", and a report that cannot answer it is asking to be
	// taken on trust. Marked so the gap between mail volume and CVE volume is
	// visible rather than inferred.
	if len(scan.Subjects) > 0 {
		b.WriteString("\n## Emails read this run\n\n")
		fmt.Fprintf(&b, "%d message(s) in the window, %d mentioning a CVE.\n\n",
			scan.Messages, scan.WithCVEs)
		b.WriteString("| CVE? | Received | Subject |\n|---|---|---|\n")
		for _, e := range scan.Subjects {
			mark := "-"
			if e.HasCVE {
				mark = "yes"
			}
			subj := strings.TrimSpace(e.Subject)
			if subj == "" {
				subj = "(no subject)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n",
				mark, e.Received.Format("2006-01-02 15:04"), escape(subj))
		}
		b.WriteString("\n")
	}

	// 0600, not 0644 - this file is sensitive even when redacted, because the
	// CVE/host-count pairs alone describe where the environment is weak.
	//
	// path comes from REPORT_PATH in the service configuration.
	// The mode is the control that matters here and it is deliberately 0600;
	// see the package comment.
	return os.WriteFile(path, []byte(b.String()), 0600)
}

func escape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
