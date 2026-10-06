package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	CVE       string `json:"cve"`
	CVSS      any    `json:"cvss"` // number in the JSON, printed as text
	KEV       any    `json:"kev"`  // 1/0, sometimes true/false
	KEVDue    string `json:"kev_due"`
	KEVName   string `json:"kev_name"`
	Priority  string `json:"priority"` // "Sev5".."Sev1"
	QIDs      string `json:"qids"`     // comma-separated
	HostCount int    `json:"host_count"`
	Status    string `json:"status"`
	Published string `json:"published"`
	LastSeen  string `json:"last_seen"`
	Desc      string `json:"description"`
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
	case int:
		// encoding/json never produces this - every JSON number arrives as a
		// float64 - but truthy takes `any`, and a caller constructing a row
		// in Go writes 1, not 1.0. Silently reading that as false made two
		// tests select the wrong findings, which is a small taste of what it
		// would do to a KEV flag in production.
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
		// The scanner's count beats the digest's, being the fresher of the
		// two and the one the host names came from. Shared with the
		// follow-up pass, so both compare a ticket on the same numbers.
		applyLookup(&f, res)
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

// ─── closing the loop back to the findings database ─────────────────────────

// recordRemediationNote tells fleet-db that a CVE has been handed to somebody.
//
// WHY THIS MATTERS MORE THAN IT LOOKS. `fleet-db findings --stale-days N` uses
// "remediation_note IS NULL" to decide what counts as un-actioned, and nothing
// could write that column - so a CVE with an open ticket was reported as
// ignored, forever. The orchestrator escalated three KEV CVEs as having "no
// remediation_note on any" on the same night their tickets were filed.
//
// Shelling out to a Python script from Go looks like the wrong shape until you
// remember why Python is still here: Go has no stdlib SQL driver, and adding a
// dependency to write one column is a worse trade than exec'ing the tool that
// already owns the schema.
//
// NEVER FATAL. The ticket is the deliverable and it already exists by the time
// this runs; failing the lane because a note did not land would turn a
// bookkeeping miss into a missing ticket.
func recordRemediationNote(cve, note string, warn func(string, ...any)) {
	db, err := fleetDBPath()
	if errors.Is(err, errNoFleetLayout) {
		// Running off the fleet host - a workstation, a test. There is no
		// findings database to note anything in, and warning about it on
		// every run would teach the reader to skip the warnings that matter.
		return
	}
	if err != nil {
		warn("%s has a ticket but is still recorded as un-actioned: %s", cve, err)
		return
	}
	// #nosec G204,G702 -- BOTH, and the pair is the point.
	//
	// G702 is the taint rule and fired until fleetDBPath() below existed;
	// adding the validator removed the flow it was reporting, at which point
	// the older G204 ("subprocess launched with variable") surfaced on the
	// same line - it does not care where the variable came from, only that
	// one exists. Annotating just the rule that happens to be firing today
	// leaves the gate red the next time gosec changes which one it prefers.
	//
	// G702 is taint analysis and it is correct that this path
	// derives from an environment variable. The control is fleetDBPath()
	// above, which refuses a relative FLEET_CODE and requires the resolved
	// path to be a regular file named exactly "fleet-db" - so the only thing
	// that can run here is the tool that owns the schema. The analysis tracks
	// os.Getenv to this call and stops; it does not model validators, the
	// same way G706 does not model sanitisers.
	//
	// There is no shell. cve and note are separate argv entries, so neither
	// can introduce a further argument however they are spelled.
	out, err := exec.Command(db, "note", cve, note).CombinedOutput()
	if err != nil {
		warn("could not record the remediation note for %s: %s: %s",
			cve, err, strings.TrimSpace(string(out)))
	}
}

// fleetDBPath resolves and validates the path to fleet-db.
//
// Validation rather than a bare suppression. FLEET_CODE is set by the systemd
// unit and anybody who can change it can already run code as this account, so
// the taint finding is not an escalation - but "not an escalation" is a
// weaker claim than "checked", and the check costs four lines.
//
// Absent FLEET_CODE is not an error: cti-jira runs on a workstation during
// development, where there is no fleet layout and nothing to record to.
func fleetDBPath() (string, error) {
	code := strings.TrimSpace(os.Getenv("FLEET_CODE"))
	if code == "" {
		return "", errNoFleetLayout
	}
	if !filepath.IsAbs(code) {
		return "", fmt.Errorf("FLEET_CODE is not an absolute path (%q)", code)
	}
	db := filepath.Join(code, "bin", "fleet-db")
	// Join already cleans the path; this asserts what we ended up with rather
	// than trusting that it did.
	if filepath.Base(db) != "fleet-db" {
		return "", fmt.Errorf("resolved to %q, which is not fleet-db", db)
	}
	// #nosec G703 -- same taint flow, same validator. The path is now known
	// absolute and known to end in bin/fleet-db.
	fi, err := os.Stat(db)
	if err != nil {
		return "", fmt.Errorf("fleet-db not found at %s", db)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", db)
	}
	return db, nil
}

// errNoFleetLayout means there is nothing to record to, which is normal off
// the fleet host and must not be reported as a failure.
var errNoFleetLayout = errors.New(
	"FLEET_CODE is unset, so there is no findings database to note it in")

// RemediationNote is what gets stored: the key, and a link somebody can click
// out of a database row.
func RemediationNote(ref TicketRef, now time.Time) string {
	if ref.Key == "" {
		return ""
	}
	s := ref.Key
	if ref.URL != "" {
		s += " " + ref.URL
	}
	return s + " (filed " + now.Format("2006-01-02") + ")"
}
