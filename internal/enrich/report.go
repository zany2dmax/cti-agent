package enrich

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// cveRE is a whole CVE ID. \d{4,}: the sequence number has a four-digit
// minimum and no maximum, so a longer ID is not skipped without comment.
var cveRE = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// IsCVE reports whether s is exactly one CVE ID, in any case.
func IsCVE(s string) bool { return cveRE.MatchString(s) }

// mailSource is the Mail Source cell as "trusted", "unverified" or ""
// (unknown). Only the two words the agent writes count, so an unexpected
// cell can neither clear nor set the unverified label.
func mailSource(cell string) string {
	v := strings.ToLower(strings.TrimSpace(cell))
	if v == "trusted" || v == "unverified" {
		return v
	}
	return ""
}

// splitCells splits a table row's body on unescaped pipes. The agent writes
// a pipe inside a cell as \|, and a plain split would shift every column
// after it.
func splitCells(body string) []string {
	var cells []string
	start := 0
	for i := 0; i < len(body); i++ {
		if body[i] == '|' && (i == 0 || body[i-1] != '\\') {
			cells = append(cells, body[start:i])
			start = i + 1
		}
	}
	return append(cells, body[start:])
}

func asInt(v string) int {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// ParseReport reads the agent's markdown table.
//
// Columns: CVE | Status | Provider | External IDs | Host Count | Max Score |
// Last Seen | Sample Hosts | Reason | Detection Titles | Mail Source | Asked
//
// The last three were added later, so a report without them still parses:
// a missing Mail Source is "" (unknown), and anything but "asked" in Asked is
// not asked. Older reports combined Sample Hosts and Reason into one column;
// that 8-column form routes the cell by whether the lookup found hosts. A
// CVE that appears twice keeps its last row.
func ParseReport(path string) (map[string]*Finding, error) {
	// #nosec G304 -- the report path is the runner's own argument.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	findings := map[string]*Finding{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "|---") || strings.Contains(line, "| CVE |") {
			continue
		}
		body := line[1:]
		if strings.HasSuffix(line, "|") && !strings.HasSuffix(line, "\\|") {
			body = line[1 : len(line)-1]
		}
		parts := splitCells(body)
		cells := make([]string, len(parts))
		for i, c := range parts {
			cells[i] = strings.ReplaceAll(strings.TrimSpace(c), "\\|", "|")
		}
		if len(cells) < 8 || !IsCVE(cells[0]) {
			continue
		}
		f := &Finding{
			CVE:         strings.ToUpper(cells[0]),
			Status:      or(cells[1], "UNKNOWN"),
			Provider:    or(cells[2], "unknown"),
			QIDs:        cells[3],
			HostCount:   asInt(cells[4]),
			QualysScore: asInt(cells[5]),
			LastSeen:    cells[6],
			FromReport:  true,
		}
		if len(cells) >= 9 {
			f.SampleHosts, f.ProviderReason = cells[7], cells[8]
		} else if f.HostCount > 0 {
			f.SampleHosts = cells[7]
		} else {
			f.ProviderReason = cells[7]
		}
		f.DetectionTitles = []string{}
		if len(cells) >= 10 {
			for _, t := range strings.Split(cells[9], " ; ") {
				if t = strings.TrimSpace(t); t != "" {
					f.DetectionTitles = append(f.DetectionTitles, t)
				}
			}
		}
		if len(cells) >= 11 {
			f.MailSource = mailSource(cells[10])
		}
		f.Asked = len(cells) >= 12 && strings.ToLower(strings.TrimSpace(cells[11])) == "asked"
		findings[f.CVE] = f
	}
	return findings, nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Subject is one line of the "Emails read this run" table.
type Subject struct {
	HasCVE   bool   `json:"has_cve"`
	Received string `json:"received"`
	Subject  string `json:"subject"`
}

const subjectsHeading = "## Emails read this run"

// ParseSubjects reads the "Emails read this run" table the agent appends:
// CVE? | Received | Subject. A report without it gives an empty list.
//
// Cells are split on unescaped pipes only, as in ParseReport: the agent
// writes a pipe inside a subject as \|. The Python lane split on every
// pipe, so "Log4j | again" reached the digest as "Log4j \".
func ParseSubjects(path string) []Subject {
	out := []Subject{}
	// #nosec G304 -- the report path is the runner's own argument.
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	text := string(raw)
	i := strings.Index(text, subjectsHeading)
	if i < 0 {
		return out
	}
	for _, line := range strings.Split(text[i+len(subjectsHeading):], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "|---") {
			continue
		}
		body := line[1:]
		if strings.HasSuffix(line, "|") && !strings.HasSuffix(line, "\\|") {
			body = line[1 : len(line)-1]
		}
		cells := splitCells(body)
		for k := range cells {
			cells[k] = strings.TrimSpace(cells[k])
		}
		if len(cells) < 3 || cells[0] == "CVE?" {
			continue
		}
		out = append(out, Subject{
			HasCVE:   strings.ToLower(cells[0]) == "yes",
			Received: cells[1],
			Subject:  strings.ReplaceAll(cells[2], "\\|", "|"),
		})
	}
	return out
}

// metaFields are the header facts the digest states its provenance with, in
// the order they are written out.
var metaFields = []struct {
	key string
	re  *regexp.Regexp
}{
	{"mailbox", regexp.MustCompile("Mailbox:\\s*`([^`]+)`")},
	{"since", regexp.MustCompile("Lookback since:\\s*`([^`]+)`")},
	// Both spellings: "Emails inspected" was the old, misleading count.
	{"emails", regexp.MustCompile("Emails (?:in window|inspected):\\s*`([^`]+)`")},
	{"with_cves", regexp.MustCompile("Emails mentioning a CVE:\\s*`([^`]+)`")},
	{"cves_found", regexp.MustCompile("Distinct CVEs extracted:\\s*`([^`]+)`")},
	{"provider", regexp.MustCompile("Lookup provider:\\s*`([^`]+)`")},
	{"generated", regexp.MustCompile("Generated:\\s*`([^`]+)`")},
}

// ParseMeta pulls the header facts from the first 4000 characters of the
// report. A missing file gives no facts, not an error.
func ParseMeta(path string) Meta {
	// #nosec G304 -- the report path is the runner's own argument.
	raw, err := os.ReadFile(path)
	if err != nil {
		return Meta{}
	}
	head := string(raw)
	if utf8.RuneCountInString(head) > 4000 {
		head = string([]rune(head)[:4000])
	}
	var m Meta
	for _, f := range metaFields {
		if g := f.re.FindStringSubmatch(head); g != nil {
			m = append(m, [2]string{f.key, g[1]})
		}
	}
	return m
}
