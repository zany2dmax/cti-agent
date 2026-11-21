// cti-triage turns one threat-intel advisory into facts from our own tools.
//
//	cti-triage --show-input --message advisory.txt          # what the reader would be shown; no model, no lookups
//	cti-triage --read       --message advisory.txt          # the reader's answer, checked against the advisory
//	cti-triage --facts      --message advisory.txt          # reader, then Falcon lookups: the fact sheet
//	cti-triage --facts      --message advisory.txt --subjects-file saved.json   # replay, no model call
//	cti-triage --judge      --message advisory.txt          # reader, lookups, then the judge: checked verdicts
//	cti-triage --judge      --message advisory.txt --facts-file sheet.json      # judge a saved sheet, no lookups
//	cti-triage --show-judge-input --message advisory.txt --facts-file sheet.json # what the judge would be shown
//	cti-triage --batch input.json --out advisories.json    # the digest's run: every advisory ingest saved
//
// # WHAT IT IS FOR
//
// Phase 3 of advisory triage (the triage redesign plan). A no-tools model,
// the reader, says which products, versions and techniques an advisory
// concerns. It never sees our data. Code removes every claim the advisory
// does not support, then looks the rest up in Falcon: which of those
// products we run, whether our hosts saw the advisory's indicators, and
// whether Falcon has alerted on its techniques in the last 30 days.
//
// Phase 4: --judge hands that fact sheet, and never the advisory, to a
// second no-tools model, the judge, which says per subject whether it is
// worth a person's time and cites the facts it relied on. Code checks every
// claim against those facts (triage.VerifyJudgement), raises what it knows
// to be worth a look, and reports indicator sightings itself, even when the
// judge fails. Putting the result in the Daily Brief is the next step; until
// then this is run by hand, and it writes nothing.
//
// # COST
//
// --read and --facts make one model call each, --judge two (one with
// --subjects-file, none with --judgement-file too), and each call's tokens
// and cost go to stderr. --show-input and --show-judge-input make none.
//
// # SETTINGS
//
// TRIAGE_MODEL (required for a model call), CLAUDE_BIN,
// TRIAGE_READER_INSTRUCTIONS (default $FLEET_CODE/agents/triage-reader/CLAUDE.md),
// TRIAGE_JUDGE_MODEL (default TRIAGE_MODEL), TRIAGE_JUDGE_INSTRUCTIONS
// (default $FLEET_CODE/agents/triage-judge/CLAUDE.md),
// TRIAGE_BLIND_SPOTS (free text naming what Falcon cannot see, e.g. sites
// without the sensor), and the FALCON_* settings cti-falcon uses.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/falcon"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/triage"
)

const (
	exitOK    = 0
	exitErr   = 1
	exitUsage = 2

	maxMessage = 256 << 10
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// Seams for tests.
var (
	now        = time.Now
	factSource = func() (triage.FactSource, func(), error) {
		c, err := falcon.New(os.Getenv("FALCON_BASE_URL"), os.Getenv("FALCON_CLIENT_ID"), fleetenv.Secret("FALCON_CLIENT_SECRET"))
		if err != nil {
			return nil, nil, err
		}
		return c, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = c.Revoke(ctx)
		}, nil
	}
	callModel = func(ctx context.Context, m triage.ModelCall, input string) (string, triage.Usage, error) {
		return m.Run(ctx, input)
	}
)

func run(args []string, stdout, stderr io.Writer) int {
	fleetenv.Load()
	fs := flag.NewFlagSet("cti-triage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showInput := fs.Bool("show-input", false, "print what the reader would be shown; no model call, no lookups")
	read := fs.Bool("read", false, "run the reader and print its answer, checked against the advisory")
	facts := fs.Bool("facts", false, "run the reader, then look its answer up in Falcon: the fact sheet")
	message := fs.String("message", "", "the advisory: a text file holding its body")
	subject := fs.String("subject", "", "the advisory's subject line, if known")
	sender := fs.String("sender", "", "the advisory's sender, if known")
	judge := fs.Bool("judge", false, "run the reader, the lookups and then the judge: checked verdicts")
	showJudgeInput := fs.Bool("show-judge-input", false, "with --facts-file: print what the judge would be shown; no model call, no lookups")
	subjectsFile := fs.String("subjects-file", "", "with --facts or --judge: a saved reader answer to use instead of a model call")
	factsFile := fs.String("facts-file", "", "with --judge or --show-judge-input: a saved fact sheet (--facts --json) instead of the reader and the lookups")
	judgementFile := fs.String("judgement-file", "", "with --judge: a saved judge answer to check instead of a model call")
	batch := fs.String("batch", "", "triage every advisory in this file (cti-agent --advisories-out) and write the report to --out")
	outFile := fs.String("out", "", "with --batch: where to write the report (cti-advisories/1)")
	batchTimeout := fs.Duration("batch-timeout", 20*time.Minute, "with --batch: stop starting advisories after this long; the rest are listed as not triaged")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long (with --batch: per advisory)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: cti-triage --show-input | --read | --facts | --judge | --show-judge-input  --message FILE [--subject S] [--sender S] [--subjects-file F] [--facts-file F] [--judgement-file F] [--json] [--timeout D]\n       cti-triage --batch FILE --out FILE [--timeout D] [--batch-timeout D]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	logf := func(format string, a ...any) { _, _ = fmt.Fprintf(stderr, "[triage] "+format+"\n", a...) }
	if *batch != "" || *outFile != "" {
		alone := !*showInput && !*read && !*facts && !*judge && !*showJudgeInput && *message == "" &&
			*subjectsFile == "" && *factsFile == "" && *judgementFile == "" && !*asJSON
		if *batch == "" || *outFile == "" || !alone || fs.NArg() > 0 {
			fs.Usage()
			return exitUsage
		}
		return runBatch(*batch, *outFile, *timeout, *batchTimeout, logf)
	}
	modes := 0
	for _, on := range []bool{*showInput, *read, *facts, *judge, *showJudgeInput} {
		if on {
			modes++
		}
	}
	bad := modes != 1 || fs.NArg() > 0 || *message == "" ||
		(*subjectsFile != "" && !*facts && !*judge) ||
		(*factsFile != "" && !*judge && !*showJudgeInput) ||
		(*factsFile != "" && *subjectsFile != "") ||
		(*showJudgeInput && *factsFile == "") ||
		(*judgementFile != "" && !*judge)
	if bad {
		fs.Usage()
		return exitUsage
	}

	body, err := readCapped(*message, maxMessage)
	if err != nil {
		logf("error  : --message: %v", err)
		return exitErr
	}
	msg := triage.Message{ID: filepath.Base(*message), Received: now(), Sender: *sender, Subject: *subject, Body: body}
	ex := triage.Extract(body)
	input := triage.RenderInput(msg, ex)
	if *showInput {
		_, _ = io.WriteString(stdout, input)
		return exitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *factsFile != "" {
		b, err := readBytesCapped(*factsFile, maxMessage)
		if err != nil {
			logf("error  : --facts-file: %v", err)
			return exitErr
		}
		var sheet triage.FactSheet
		if err := json.Unmarshal(b, &sheet); err != nil || sheet.Schema != triage.FactsSchema {
			logf("error  : --facts-file: not a %s sheet", triage.FactsSchema)
			return exitErr
		}
		in := triage.BuildJudgeInput(msg, sheet)
		if *showJudgeInput {
			_, _ = io.WriteString(stdout, in.Text)
			return exitOK
		}
		return runJudge(ctx, msg, sheet, in, *judgementFile, *asJSON, stdout, logf)
	}

	var answer []byte
	if *subjectsFile != "" {
		if answer, err = readBytesCapped(*subjectsFile, maxMessage); err != nil {
			logf("error  : --subjects-file: %v", err)
			return exitErr
		}
	} else {
		instr, err := readCapped(instructionsPath(), 64<<10)
		if err != nil {
			logf("error  : the reader's instructions: %v", err)
			return exitErr
		}
		m := triage.ModelCall{Bin: os.Getenv("CLAUDE_BIN"), Model: os.Getenv("TRIAGE_MODEL"), Instructions: instr}
		out, usage, err := callModel(ctx, m, input)
		logf("reader : %s", usage)
		if err != nil {
			logf("error  : reader: %v", err)
			return exitErr
		}
		answer = []byte(out)
	}
	subj, err := triage.ParseSubjects(answer)
	if err != nil {
		logf("error  : %v", err)
		return exitErr
	}
	removed := triage.VerifySubjects(subj, body, ex.Techniques)

	if *read {
		if *asJSON {
			// The checked answer alone, so it can be saved and replayed with
			// --subjects-file; what was removed goes to stderr.
			for _, v := range removed {
				logf("removed: %s", s(v.String()))
			}
			return writeJSON(stdout, subj)
		}
		printSubjects(stdout, subj, removed)
		return exitOK
	}

	src, done, err := factSource()
	if err != nil {
		logf("error  : %v", err)
		return exitErr
	}
	defer done()
	sheet := triage.Gather(ctx, src, body, ex, subj, removed, now(), os.Getenv("TRIAGE_BLIND_SPOTS"))
	if ctx.Err() != nil {
		logf("error  : gave up after %s; the sheet below is incomplete", *timeout)
	}
	if *judge {
		if ctx.Err() != nil {
			// No time left for the judge; code still reports the sightings.
			runJudge(context.Background(), msg, sheet, triage.BuildJudgeInput(msg, sheet), "-", *asJSON, stdout, logf)
			return exitErr
		}
		return runJudge(ctx, msg, sheet, triage.BuildJudgeInput(msg, sheet), *judgementFile, *asJSON, stdout, logf)
	}
	if *asJSON {
		if code := writeJSON(stdout, sheet); code != exitOK {
			return code
		}
	} else {
		printSheet(stdout, sheet)
	}
	if ctx.Err() != nil {
		return exitErr
	}
	return exitOK
}

func instructionsPath() string { return agentFile("TRIAGE_READER_INSTRUCTIONS", "triage-reader") }

func agentFile(env, agent string) string {
	if p := strings.TrimSpace(os.Getenv(env)); p != "" {
		return p
	}
	code := strings.TrimSpace(os.Getenv("FLEET_CODE"))
	if code == "" {
		code = "/opt/cti-agent"
	}
	return filepath.Join(code, "agents", agent, "CLAUDE.md")
}

// runJudge asks the judge (or reads a saved answer, or, with "-", skips it),
// checks the answer and prints the verdicts. Whatever happens to the judge,
// the verdicts are printed: sightings and code's own floors do not depend
// on it. A judge that failed is exit 1, after the output.
func runJudge(ctx context.Context, msg triage.Message, sheet triage.FactSheet, in triage.JudgeInput, saved string, asJSON bool, stdout io.Writer, logf func(string, ...any)) int {
	j, down, _ := askJudge(ctx, in, saved, logf)
	v := triage.VerifyJudgement(j, in, sheet, msg.ID, down)
	if down != "" {
		logf("error  : %s", s(down))
	}
	for _, r := range v.Removed {
		logf("removed: %s", s(r))
	}
	code := exitOK
	if asJSON {
		code = writeJSON(stdout, v)
	} else {
		printVerdicts(stdout, v)
	}
	if down != "" {
		return exitErr
	}
	return code
}

// askJudge gets the judge's parsed answer: from a saved file, from a model
// call, or (saved "-") not at all. down is why there is no answer.
func askJudge(ctx context.Context, in triage.JudgeInput, saved string, logf func(string, ...any)) (*triage.Judgement, string, triage.Usage) {
	var usage triage.Usage
	var raw []byte
	switch {
	case saved == "-":
		return nil, "the run timed out before the judge was asked", usage
	case saved != "":
		b, err := readBytesCapped(saved, maxMessage)
		if err != nil {
			return nil, "--judgement-file: " + err.Error(), usage
		}
		raw = b
	default:
		instr, err := readCapped(agentFile("TRIAGE_JUDGE_INSTRUCTIONS", "triage-judge"), 64<<10)
		if err != nil {
			return nil, "the judge's instructions: " + err.Error(), usage
		}
		model := strings.TrimSpace(os.Getenv("TRIAGE_JUDGE_MODEL"))
		if model == "" {
			model = os.Getenv("TRIAGE_MODEL")
		}
		m := triage.ModelCall{Bin: os.Getenv("CLAUDE_BIN"), Model: model, Instructions: instr}
		out, u, err := callModel(ctx, m, in.Text)
		usage = u
		logf("judge  : %s", u)
		if err != nil {
			return nil, "judge: " + err.Error(), usage
		}
		raw = []byte(out)
	}
	j, err := triage.ParseJudgement(raw)
	if err != nil {
		return nil, err.Error(), usage
	}
	return j, "", usage
}

func printVerdicts(w io.Writer, v triage.Verdicts) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	if len(v.Sightings) > 0 {
		p("SIGHTINGS (code, whatever the judge says)")
		for _, i := range v.Sightings {
			p("  >>> %s (%s) seen on %d of our host(s)", s(i.Value), s(i.Type), i.Hosts)
		}
		p("")
	}
	if v.JudgeDown != "" {
		p("JUDGE UNAVAILABLE: %s - verdicts below are code's alone", s(v.JudgeDown))
		p("")
	}
	for _, x := range v.Verdicts {
		name := x.Title
		if x.Name != "" {
			name += " (" + x.Name + ")"
		}
		p("%s %s: %s", x.Subject, strings.ToUpper(x.Relevance), s(name))
		by := "the judge's words"
		if x.ReasonBy == "code" {
			by = "code"
		}
		p("    why     : %s (%s)", s(x.Reason), by)
		if x.RaisedBy != "" {
			p("    raised  : %s (code)", s(x.RaisedBy))
		}
		for _, f := range x.Facts {
			p("    fact %-3s: %s", f.ID, s(f.Text))
		}
		for _, c := range x.Checks {
			p("    check   : %s (the judge's words)", s(c))
		}
	}
	p("\nNOT COVERED")
	for _, g := range v.Gaps {
		p("  %s", s(g))
	}
	if len(v.Removed) > 0 {
		p("\nJUDGE CLAIMS REMOVED: %d", len(v.Removed))
		for _, r := range v.Removed {
			p("  %s", s(r))
		}
	}
}

func readBytesCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a path the operator named on the command line
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

func readCapped(path string, max int64) (string, error) {
	b, err := readBytesCapped(path, max)
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return "", errors.New("empty")
	}
	return string(b), nil
}

func writeJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return exitErr
	}
	return exitOK
}

// s sanitises anything that came from the advisory, the model or the API
// before it reaches the terminal.
func s(v string) string { return safelog.LineMax(v, 160) }

func printSubjects(w io.Writer, subj *triage.Subjects, removed []triage.SubjectViolation) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	if subj.Refusal != nil {
		p("REFUSED (the reader's words): %s", s(subj.Refusal.Reason))
		return
	}
	p("subjects: %d", len(subj.Items))
	for _, it := range subj.Items {
		name := it.Product
		if it.Vendor != "" {
			name = it.Vendor + " / " + name
		}
		p("- %s (title in the reader's words): %s", s(it.Title), s(name))
		if it.Affected != "" {
			p("    affected  : %s (the reader's words)", s(it.Affected))
		}
		if it.FixedIn != "" {
			p("    fixed in  : %s (found in the advisory)", s(it.FixedIn))
		}
		if len(it.Techniques) > 0 {
			p("    techniques: %s", s(strings.Join(it.Techniques, ", ")))
		}
		if len(it.Inferred) > 0 {
			p("    inferred  : %s (named by the reader, not the advisory)", s(strings.Join(it.Inferred, ", ")))
		}
		for _, q := range it.Quotes {
			p("    quote     : %q", s(q))
		}
	}
	for _, line := range triage.CVEItemLines(subj) {
		p("- set aside, names a CVE (the CVE digest's): %s", s(line))
	}
	if len(removed) > 0 {
		p("removed (not supported by the advisory): %d", len(removed))
		for _, v := range removed {
			p("  %s", s(v.String()))
		}
	}
}

func printSheet(w io.Writer, f triage.FactSheet) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	if f.Sensors > 0 {
		p("Falcon has seen %d hosts in the last 30 days.%s", f.Sensors, blind(f.BlindSpots))
	} else {
		p("Falcon's host count is unavailable.%s", blind(f.BlindSpots))
	}
	if f.Refused != "" {
		p("READER REFUSED (its words): %s - only the advisory's own indicators and techniques were looked up", s(f.Refused))
	}

	p("\nINDICATORS")
	hits := 0
	for _, i := range f.Indicators {
		switch {
		case i.Error != "":
			p("  %-40s LOOKUP FAILED: %s", s(i.Value), s(i.Error))
		case i.Skipped != "":
			p("  %-40s not looked up: %s", s(i.Value), s(i.Skipped))
		case i.Hosts > 0:
			hits++
			p("  %-40s SEEN ON %d HOST(S)", s(i.Value), i.Hosts)
		default:
			p("  %-40s not seen", s(i.Value))
		}
	}
	if len(f.Indicators) == 0 {
		p("  none in the advisory")
	} else if hits > 0 {
		p("  >>> %d indicator(s) seen on our hosts", hits)
	}

	p("\nPRODUCTS")
	if len(f.Subjects) == 0 {
		p("  none named")
	}
	for _, sf := range f.Subjects {
		name := sf.Product
		if sf.Vendor != "" {
			name = sf.Vendor + " / " + sf.Product
		}
		if name == "" {
			name = sf.Title
		}
		switch {
		case sf.Error != "":
			p("  %s: LOOKUP FAILED: %s", s(name), s(sf.Error))
			continue
		case sf.Skipped != "":
			p("  %s: not looked up: %s", s(name), s(sf.Skipped))
			continue
		case len(sf.Apps) == 0:
			p("  %s: not installed on any host Falcon sees", s(name))
			continue
		}
		lb := ""
		if sf.Truncated {
			lb = " (counts are lower bounds)"
		}
		p("  %s: %d installed application(s) match%s", s(name), len(sf.Apps), lb)
		for _, a := range sf.Apps {
			vm := ""
			if sf.Vendor != "" && !a.VendorMatches {
				vm = "  [vendor differs]"
			}
			p("    %s / %s - %d host(s)%s", s(a.Vendor), s(a.Name), a.Hosts, vm)
			if a.BelowFixed != nil {
				line := fmt.Sprintf("      below fixed %s: about %d host(s)", s(sf.FixedIn), *a.BelowFixed)
				if a.UncomparedHosts > 0 {
					line += fmt.Sprintf("; %d on versions that can't be compared", a.UncomparedHosts)
				}
				p("%s", line)
			}
			p("      versions: %s", counts(a.Versions, a.OtherVersions))
			if len(a.HostTypes) > 0 {
				p("      hosts   : %s", counts(a.HostTypes, 0))
			}
			if len(a.Exposure) > 0 {
				p("      exposure: %s", counts(a.Exposure, 0))
			}
			if a.SuspiciousHosts > 0 {
				p("      SUSPICIOUS: Falcon flags it on %d host(s)", a.SuspiciousHosts)
			}
		}
	}

	p("\nTECHNIQUES (Falcon alerts, last 30 days)")
	if len(f.Techniques) == 0 {
		p("  none")
	}
	for _, t := range f.Techniques {
		src := ""
		if t.Source == "reader" {
			src = " (inferred by the reader)"
		}
		as := ""
		if t.Asked != "" && t.Asked != t.ID {
			as = " as " + t.Asked
		}
		switch {
		case t.Error != "":
			p("  %s%s%s: LOOKUP FAILED: %s", s(t.ID), as, src, s(t.Error))
		case t.Skipped != "":
			p("  %s%s: not looked up: %s", s(t.ID), src, s(t.Skipped))
		default:
			p("  %s%s%s: %d alert(s)", s(t.ID), as, src, t.Alerts)
		}
	}
	if len(f.ReaderErrors) > 0 {
		p("\nREADER CLAIMS REMOVED (not supported by the advisory): %d", len(f.ReaderErrors))
		for _, e := range f.ReaderErrors {
			p("  %s", s(e))
		}
	}
}

func blind(b string) string {
	if b == "" {
		return " Anything without the Falcon sensor is not covered."
	}
	return " Not covered: " + s(b) + "."
}

func counts(m map[string]int, more int) string {
	type kv struct {
		k string
		v int
	}
	var xs []kv
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].v != xs[j].v {
			return xs[i].v > xs[j].v
		}
		return xs[i].k < xs[j].k
	})
	var parts []string
	for _, x := range xs {
		parts = append(parts, fmt.Sprintf("%s (%d)", safelog.LineMax(x.k, 60), x.v))
	}
	if more > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", more))
	}
	return strings.Join(parts, ", ")
}
