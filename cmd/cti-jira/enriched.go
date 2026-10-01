package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
)

// enrichedRow mirrors one finding in the digest's enriched JSON.
//
// Only the fields this lane needs. Deliberately NOT a shared type with the
// Python side: enrich.py owns that file's shape, and pinning it in Go would
// make a harmless new column in the digest a compile error here.
//
// Every field is read defensively. A missing one means a smaller ticket, not
// a failed run - the daily security email must not depend on this lane being
// happy with the data.
type enrichedRow struct {
	CVE        string `json:"cve"`
	CVSS       any    `json:"cvss"` // number in the JSON, printed as text
	KEV        any    `json:"kev"`  // 1/0, sometimes true/false
	KEVDue     string `json:"kev_due"`
	KEVName    string `json:"kev_name"`
	Priority   string `json:"priority"` // "Sev5".."Sev1"
	QIDs       string `json:"qids"`     // comma-separated
	HostCount  int    `json:"host_count"`
	Status     string `json:"status"`
	Published  string `json:"published"`
	LastSeen   string `json:"last_seen"`
	Desc       string `json:"description"`
}

type enrichedFile struct {
	Generated string        `json:"generated"`
	Findings  []enrichedRow `json:"findings"`
}

// loadEnriched reads the digest's output.
func loadEnriched(path string) (enrichedFile, error) {
	// #nosec G304 -- an operator-supplied --from-enriched path, or the one
	// run-digest just wrote. Same trust level as every other lane's input.
	raw, err := os.ReadFile(path)
	if err != nil {
		return enrichedFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var f enrichedFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return enrichedFile{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return f, nil
}

// severity turns "Sev5" into 5.
//
// Also accepts the old "P1".."P4" scale, because an enriched file written
// before the rename can still be replayed, and a lane that silently scores
// every old row as 0 would file nothing and say nothing about why.
func severity(p string) int {
	p = strings.TrimSpace(p)
	if n, err := strconv.Atoi(strings.TrimPrefix(p, "Sev")); err == nil && n >= 1 && n <= 5 {
		return n
	}
	// P1 was the TOP of the old scale, Sev5 is the top of the new one.
	switch strings.ToUpper(p) {
	case "P1":
		return 5
	case "P2":
		return 4
	case "P3":
		return 3
	case "P4":
		return 2
	}
	return 0
}

// truthy reads the KEV flag, which has been 1, "1" and true across versions.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "1" || s == "true" || s == "yes"
	}
	return false
}

func asText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func splitQIDs(s string) []string {
	var out []string
	for _, q := range strings.Split(s, ",") {
		if q = strings.TrimSpace(q); q != "" {
			out = append(out, q)
		}
	}
	sort.Strings(out)
	return out
}

// toFinding converts a row, WITHOUT host names - those come from the scanner.
func (r enrichedRow) toFinding() jira.Finding {
	f := jira.Finding{
		CVE:       strings.TrimSpace(r.CVE),
		QIDs:      splitQIDs(r.QIDs),
		KEV:       truthy(r.KEV),
		Severity:  severity(r.Priority),
		CVSS:      asText(r.CVSS),
		Title:     strings.TrimSpace(r.KEVName),
		HostCount: r.HostCount,
	}
	if f.Title == "" {
		f.Title = firstSentence(r.Desc)
	}
	if d, err := time.Parse("2006-01-02", strings.TrimSpace(r.KEVDue)); err == nil {
		f.KEVDueOn = d
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(r.Published)); err == nil {
		f.FirstSeen = t
	}
	if len(f.QIDs) > 0 {
		// The query that reproduces the ticket's host list in the console.
		// Built from the QIDs rather than the CVE because that is what the
		// scanner's own UI filters on.
		f.QQL = "vulnerabilities.vulnerability.qid:[" + strings.Join(f.QIDs, ",") + "]"
	}
	return f
}

// firstSentence keeps a ticket title to one clause. A CVE description can run
// to several hundred characters and the whole thing in a summary is unreadable
// in a queue list.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i]
	}
	return s
}

// hostFiller fetches the full host list for one CVE. Separated so the
// selection logic can be tested without a scanner.
type hostFiller func(ctx context.Context, cve string) (vulnlookup.Result, error)

// selectForTicketing returns the findings that earn a ticket, with host names
// filled in from the scanner.
//
// ONLY the selected ones are looked up. On a normal day that is a handful of
// CVEs rather than all twenty-odd, which matters because each lookup is a
// Host Detection call against an API that rate-limits one KB request per
// subscription at a time.
//
// A lookup failure drops that one finding with a warning rather than failing
// the run. A scanner hiccup should cost one ticket, not the whole lane - and
// never the digest, which runs after this.
func selectForTicketing(ctx context.Context, rows []enrichedRow, fill hostFiller,
	warn func(string, ...any)) []jira.Finding {

	var out []jira.Finding
	for _, r := range rows {
		f := r.toFinding()
		if f.CVE == "" || !jira.ShouldFile(f) {
			continue
		}
		// Not PRESENT means the scanner has no detections, so there is
		// nothing for anybody to remediate and no host list to attach. A
		// ticket for a CVE that is not in the estate is noise aimed at IT.
		if !strings.EqualFold(strings.TrimSpace(r.Status), vulnlookup.StatusPresent) {
			continue
		}

		res, err := fill(ctx, f.CVE)
		if err != nil {
			warn("could not fetch hosts for %s, skipping it: %s", f.CVE, err)
			continue
		}
		f.Hosts = res.Hosts
		if res.HostCount > 0 {
			// The scanner's count beats the digest's, being the fresher of
			// the two and the one the host names came from.
			f.HostCount = res.HostCount
		}
		f.CountIsFloor = res.HostCountIsFloor
		if len(res.ExternalIDs) > 0 {
			f.QIDs = res.ExternalIDs
			f.QQL = "vulnerabilities.vulnerability.qid:[" + strings.Join(f.QIDs, ",") + "]"
		}
		out = append(out, f)
	}
	// Worst first, so a truncated run files the biggest exposure.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Count() > out[j].Count()
	})
	return out
}

// TicketRef is what the digest needs to render a link.
type TicketRef struct {
	Key     string `json:"key"`
	URL     string `json:"url"`
	Status  string `json:"status,omitempty"`
	Created bool   `json:"created"`
}

// TicketMap is written beside the enriched file for brief.py to read.
//
// A FILE, not a database lookup from the renderer. brief.py is stdlib Python
// with no Jira credentials and no business having any - the lane that can
// already talk to Jira does the talking, and hands the renderer a flat map.
type TicketMap struct {
	Generated string               `json:"generated"`
	Tickets   map[string]TicketRef `json:"tickets"`
}

// TicketMapPath is where it goes: next to the enriched file it describes, so
// a replay of an old day reads that day's tickets rather than today's.
func TicketMapPath(enrichedPath string) string {
	return strings.TrimSuffix(enrichedPath, ".json") + "-tickets.json"
}

// writeTicketMap writes atomically at 0600.
//
// 0600 and atomic for the same reasons as every other generated file here: it
// names internal hostnames by CVE, and a half-written map read by the
// renderer mid-write would put a truncated ticket key in a security email.
func writeTicketMap(path string, m TicketMap) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the ticket map: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s: %w", tmp, err)
	}
	return nil
}
