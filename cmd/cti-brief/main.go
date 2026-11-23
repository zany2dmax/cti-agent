// cti-brief is the @brief lane: it renders the enriched findings as the
// daily or weekly digest (internal/brief).
//
//	cti-brief --daily  --enriched enriched.json --out digest.html --text-out digest.txt
//	cti-brief --weekly --enriched weekly-enriched.json --out weekly.html
//	cti-brief --subject-only --enriched enriched.json
//	cti-brief --counts --enriched enriched.json      # "Sev5 Sev4 Sev3 Sev2 Sev1 total"
//
// Beside the enriched file it reads, when they are there: the ticket map
// cti-jira wrote (-tickets.json, with the CVEs held for approval), the
// product map cti-enrich keeps (products.json) and, for the daily, the
// advisory report cti-triage wrote (-advisories.json). It sends nothing:
// run-digest hands the files to cti-mailer.
//
// It replaced the Python brief.py, flag for flag and byte for byte.
//
// # SETTINGS
//
// FLEET_ORG (the name in the header and footer, default "Security"),
// FLEET_ATTRIBUTION and FLEET_REPO_URL (the footer credit; only http and
// https become a link), TRIAGE_ENABLED (1 shows the advisories section even
// when triage reported nothing).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/brief"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
)

func main() {
	fleetenv.Load()
	os.Exit(run(os.Args[1:], brief.EnvFromOS(), os.Getenv("TRIAGE_ENABLED"), time.Now(), os.Stdout, os.Stderr))
}

const usage = "usage: cti-brief --enriched FILE [--daily | --weekly [--advisories-dir DIR] [--week-days N]] [--subject-only | --counts] [--out FILE] [--text-out FILE]"

func run(args []string, env brief.Env, triage string, now time.Time, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cti-brief", flag.ContinueOnError)
	fs.SetOutput(stderr)
	enriched := fs.String("enriched", "", "the enriched JSON (cti-enrich, or fleet-db rollup)")
	daily := fs.Bool("daily", false, "the daily digest (the default)")
	weekly := fs.Bool("weekly", false, "the weekly digest")
	subjectOnly := fs.Bool("subject-only", false, "print the subject line only")
	countsOnly := fs.Bool("counts", false, "print the five band counts and the total as integers, for run-digest's record")
	out := fs.String("out", "", "HTML output path")
	textOut := fs.String("text-out", "", "plain-text output path")
	advDir := fs.String("advisories-dir", "",
		"weekly: the folder holding the dailies' enriched-DAY-advisories.json (default: the --enriched file's)")
	weekDays := fs.Int("week-days", 7, "weekly: how many days, up to yesterday, FLEET ADVISORIES rolls up")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *weekDays < 1 || *weekDays > 31 {
		_, _ = fmt.Fprintln(stderr, "cti-brief: --week-days must be 1 to 31")
		return 2
	}
	if fs.NArg() > 0 || *enriched == "" || (*daily && *weekly) || (*subjectOnly && *countsOnly) {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	kind := "daily"
	if *weekly {
		kind = "weekly"
	}

	raw, err := os.ReadFile(*enriched)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[brief] error: %v\n", err)
		return 1
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil || data == nil {
		if err == nil {
			err = errors.New("not a JSON object")
		}
		_, _ = fmt.Fprintf(stderr, "[brief] error: %s: %v\n", *enriched, err)
		return 1
	}
	if *countsOnly {
		// What run-digest records with the send (fleet-db sent) and says
		// after a rollup. Read before Prepare, from the file as written.
		line, err := countsLine(data)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "[brief] error: %s: %v\n", *enriched, err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, line)
		return 0
	}
	brief.Prepare(data, *enriched, kind, strings.TrimSpace(triage) == "1", now)
	if kind == "weekly" && (*advDir != "" || *weekDays != 7) {
		dir := *advDir
		if dir == "" {
			dir = filepath.Dir(*enriched)
		}
		brief.SetWeekAdvisories(data, dir, now, *weekDays)
	}

	if *subjectOnly {
		_, _ = fmt.Fprintln(stdout, brief.Subject(data, kind, now))
		return 0
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stderr, "--out is required unless --subject-only")
		return 2
	}
	if err := write(*out, brief.Render(data, kind, now, env)); err != nil {
		_, _ = fmt.Fprintf(stderr, "[brief] error: --out: %v\n", err)
		return 1
	}
	counts, _ := data["counts"].(map[string]any)
	parts := make([]string, len(brief.SevOrder))
	for i, p := range brief.SevOrder {
		v, ok := counts[p]
		if !ok {
			v = json.Number("0")
		}
		parts[i] = p + "=" + countText(v)
	}
	_, _ = fmt.Fprintf(stderr, "[brief] wrote %s (%s) %s\n", *out, kind, strings.Join(parts, " "))
	if *textOut != "" {
		if err := write(*textOut, brief.RenderText(data, kind, now, env)); err != nil {
			_, _ = fmt.Fprintf(stderr, "[brief] error: --text-out: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "[brief] wrote %s\n", *textOut)
	}
	return 0
}

func countText(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case json.Number:
		return brief.Str(x)
	}
	return brief.Str(v)
}

// write replaces path atomically, 0600: the digest names hosts.
func write(path, content string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), "."+filepath.Base(abs)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, abs)
}

// countsLine is the five band counts and the total, as run-digest used to
// read them with Python: int(counts.get(band, 0) or 0), and the total
// likewise (the number of findings when the file has none). A count that is
// not a number is an error, and run-digest records zeros and says so.
func countsLine(data map[string]any) (string, error) {
	counts, _ := data["counts"].(map[string]any)
	parts := make([]string, 0, 6)
	for _, p := range brief.SevOrder {
		n, err := pyInt(counts[p])
		if err != nil {
			return "", fmt.Errorf("counts.%s: %w", p, err)
		}
		parts = append(parts, strconv.Itoa(n))
	}
	total, ok := data["total"]
	if !ok {
		findings, _ := data["findings"].([]any)
		total = json.Number(strconv.Itoa(len(findings)))
	}
	n, err := pyInt(total)
	if err != nil {
		return "", fmt.Errorf("total: %w", err)
	}
	return strings.Join(append(parts, strconv.Itoa(n)), " "), nil
}

// pyInt is Python's int(v or 0): null, false and "" are 0, a float is cut
// toward zero, a string must hold an integer.
func pyInt(v any) (int, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case json.Number:
		if i, err := strconv.Atoi(string(x)); err == nil {
			return i, nil
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, fmt.Errorf("%q is not a number", string(x))
		}
		return int(f), nil
	case string:
		if x == "" {
			return 0, nil
		}
		i, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, fmt.Errorf("%q is not a whole number", x)
		}
		return i, nil
	}
	return 0, fmt.Errorf("%T is not a number", v)
}
