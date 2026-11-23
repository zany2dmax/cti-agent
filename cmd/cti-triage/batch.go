package main

// --batch: the digest's advisory triage. One input file from ingest (every
// message from a threat-intel sender), one report out for cti-brief. Each advisory is
// read, looked up and judged on its own, with its own timeout; a failure in
// one is recorded on it and the batch goes on. At most TRIAGE_MAX_PER_RUN
// are triaged (default 10, at most 50); the rest are listed as over the cap,
// never left out.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/triage"
)

const (
	defaultMaxPerRun = 10
	hardMaxPerRun    = 50
)

func maxPerRun() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("TRIAGE_MAX_PER_RUN")))
	switch {
	case err != nil || n < 0:
		return defaultMaxPerRun
	case n > hardMaxPerRun:
		return hardMaxPerRun
	}
	return n
}

func runBatch(inPath, outPath string, perItem, whole time.Duration, logf func(string, ...any)) int {
	in, err := triage.ReadAdvisoryInput(inPath)
	if err != nil {
		logf("error  : --batch: %v", err)
		return exitErr
	}
	if in.Refused > 0 {
		logf("warn   : --batch: %d message(s) in the input failed the checks (no usable id or time) and were not triaged", in.Refused)
	}
	rep := triage.AdvisoryReport{Schema: triage.AdvisoryReportSchema, Generated: now().UTC(),
		Read: len(in.Messages) + in.Dropped, Dropped: in.Dropped,
		Gaps: refusedGap(in.Refused)}
	msgs := triage.Order(in.Messages)
	result := func(a triage.Advisory) triage.AdvisoryResult {
		return triage.AdvisoryResult{MessageID: a.ID, Subject: a.Subject, Sender: a.Sender, Received: a.Received, Trusted: a.Trusted, Why: a.Why}
	}
	finish := func(code int) int {
		if err := triage.WriteAdvisoryReport(outPath, rep); err != nil {
			logf("error  : --out: %v", err)
			return exitErr
		}
		logf("batch  : %d read, %d triaged, $%.4f, %d tokens; wrote %s", rep.Read, rep.Triaged, rep.CostUSD, rep.Tokens, s(outPath))
		return code
	}
	skipAll := func(why string) int {
		for _, a := range msgs {
			r := result(a)
			r.Skipped = why
			rep.Results = append(rep.Results, r)
		}
		return finish(exitErr)
	}
	if len(msgs) == 0 {
		return finish(exitOK)
	}

	readerInstr, err := readCapped(instructionsPath(), 64<<10)
	if err != nil {
		logf("error  : the reader's instructions: %v", err)
		return skipAll("the reader's instructions could not be read")
	}
	src, done, err := factSource()
	if err != nil {
		logf("error  : Falcon: %v", err)
		return skipAll("Falcon could not be reached, so there was nothing to judge against")
	}
	defer done()

	// The whole batch has a deadline inside the digest's own, so the brief
	// still goes out; what it does not reach is listed, not lost.
	batchCtx, cancelBatch := context.WithTimeout(context.Background(), whole)
	defer cancelBatch()
	max := maxPerRun()
	for i, a := range msgs {
		r := result(a)
		switch {
		case i >= max:
			r.Skipped = fmt.Sprintf("over the cap of %d advisories per run (TRIAGE_MAX_PER_RUN)", max)
		case batchCtx.Err() != nil:
			r.Skipped = fmt.Sprintf("the batch ran out of time (%s)", whole)
		}
		if r.Skipped != "" {
			rep.Results = append(rep.Results, r)
			continue
		}
		ctx, cancel := context.WithTimeout(batchCtx, perItem)
		v, problems, cveItems, notIntel, u := triageOne(ctx, src, a, readerInstr, logf)
		cancel()
		r.Verdicts, r.Problems, r.CVEItems, r.NotIntel = &v, problems, cveItems, notIntel
		rep.Triaged++
		rep.CostUSD += u.CostUSD
		rep.Tokens += u.InputTokens + u.OutputTokens + u.CacheRead + u.CacheWrite
		if len(rep.Gaps) == 0 {
			rep.Gaps = v.Gaps
		}
		rep.Results = append(rep.Results, r)
	}
	return finish(exitOK)
}

// triageOne runs one advisory through the reader, the lookups and the
// judge. A reader that fails still leaves the indicators and the
// advisory's own techniques to look up; a judge that fails still leaves
// code's verdicts and the sightings.
//
// Items that name a CVE are set aside for the CVE digest. When the reader
// found nothing else, the judge is not asked: there is nothing left for it,
// and code still reports any indicator our hosts saw. When code has nothing
// to look up either, the message is not threat intel (notIntel) and nothing
// more is spent on it.
func triageOne(ctx context.Context, src triage.FactSource, a triage.Advisory, readerInstr string, logf func(string, ...any)) (triage.Verdicts, []string, []string, bool, triage.Usage) {
	var problems []string
	var total triage.Usage
	addUsage := func(u triage.Usage) {
		total.InputTokens += u.InputTokens
		total.OutputTokens += u.OutputTokens
		total.CacheRead += u.CacheRead
		total.CacheWrite += u.CacheWrite
		total.CostUSD += u.CostUSD
	}
	msg := triage.Message{ID: a.ID, Received: a.Received, Sender: a.Sender, Subject: a.Subject, Body: a.Body}
	ex := triage.Extract(a.Body)

	var subj *triage.Subjects
	var removed []triage.SubjectViolation
	m := triage.ModelCall{Bin: os.Getenv("CLAUDE_BIN"), Model: os.Getenv("TRIAGE_MODEL"), Instructions: readerInstr}
	out, u, err := callModel(ctx, m, triage.RenderInput(msg, ex))
	addUsage(u)
	logf("reader : %s: %s", s(a.Subject), u)
	if err == nil {
		subj, err = triage.ParseSubjects([]byte(out))
	}
	if err != nil {
		why := err.Error()
		if !strings.HasPrefix(why, "reader") {
			why = "reader: " + why
		}
		problems = append(problems, s(why)+" - only the advisory's own indicators and techniques were looked up")
		subj = nil
	} else {
		removed = triage.VerifySubjects(subj, a.Body, ex.Techniques)
	}

	cveItems := triage.CVEItemLines(subj)
	nothingFound := subj != nil && subj.Refusal == nil && len(subj.Items) == 0
	if nothingFound && len(cveItems) == 0 && !triage.HasLookups(a.Body, ex) {
		return triage.Verdicts{Schema: triage.VerdictsSchema, MessageID: a.ID, Sightings: []triage.IndicatorFact{},
			Verdicts: []triage.Verdict{}}, problems, nil, true, total
	}
	sheet := triage.Gather(ctx, src, a.Body, ex, subj, removed, now(), os.Getenv("TRIAGE_BLIND_SPOTS"))
	if ctx.Err() != nil {
		problems = append(problems, "timed out during the lookups; the facts are incomplete")
	}
	if nothingFound {
		return triage.Verdicts{Schema: triage.VerdictsSchema, MessageID: a.ID, Sightings: triage.Sightings(sheet),
			Gaps: triage.Gaps(sheet), Verdicts: []triage.Verdict{}}, problems, cveItems, false, total
	}
	in := triage.BuildJudgeInput(msg, sheet)
	saved := ""
	if ctx.Err() != nil {
		saved = "-"
	}
	j, down, ju := askJudge(ctx, in, saved, logf)
	addUsage(ju)
	if down != "" {
		problems = append(problems, s(down))
	}
	return triage.VerifyJudgement(j, in, sheet, a.ID, down), problems, cveItems, false, total
}

// refusedGap is the report line that says some of the day's input was not
// used, so a section that lists fewer than were saved says why.
func refusedGap(n int) []string {
	if n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d saved advisory message(s) failed the input checks and were not triaged", n)}
}
