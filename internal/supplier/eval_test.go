//go:build eval

package supplier

// The supplier judgement evaluation. It runs the REAL model on the invented
// requests in testdata/eval/cases.json, calling it exactly as run-supplier does
// (ModelArgs: no tools, no MCP, no session file), passes each answer through the
// same Judge that production uses, and reports how often the final verdict was
// the one wanted.
//
// Run by hand:   task eval:supplier
// It costs real tokens and is not deterministic, so it is never part of
// `task ship` or `task check`, and it is built only with -tags eval. Each case
// runs several times (SUPPLIER_EVAL_RUNS, default 3) and the result is a rate,
// not a pass or fail.
//
// What it fails on: a DANGEROUS result - the final verdict was No where No was
// neither wanted nor acceptable, i.e. a supplier that would have been waved
// through. Being too cautious (Unsure where a Yes or No was wanted) is reported
// as a rate, because that is what tuning the instructions is for.
//
// Settings (environment):
//   SUPPLIER_EVAL_MODEL     alias or id (default sonnet)
//   SUPPLIER_EVAL_RUNS      runs per case (default 3)
//   SUPPLIER_EVAL_PARALLEL  calls at once (default 4)
//   SUPPLIER_EVAL_ONLY      comma-separated case-name substrings to run
//   SUPPLIER_EVAL_REPORT    write the full results here as JSON
//   CLAUDE_BIN              the claude binary (default: on the path)

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type evalRun struct {
	Raw   string `json:"raw"`   // what the model said: yes, no, unsure, unparsable, or error
	Final string `json:"final"` // what the lane would act on, after code's checks
	Why   string `json:"why,omitempty"`
	Notes string `json:"notes,omitempty"`
	Err   string `json:"err,omitempty"`
}

type evalResult struct {
	Case EvalCase  `json:"case"`
	Runs []evalRun `json:"runs"`
}

func evalEnv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func evalInt(k string, def int) int {
	if n, err := strconv.Atoi(evalEnv(k, "")); err == nil && n > 0 {
		return n
	}
	return def
}

func TestEvalSupplierJudgement(t *testing.T) {
	claude := evalEnv("CLAUDE_BIN", "")
	if claude == "" {
		p, err := exec.LookPath("claude")
		if err != nil {
			t.Skip("claude is not installed (set CLAUDE_BIN)")
		}
		claude = p
	}
	instr, err := os.ReadFile("../../fleet-kit/fleet/agents/supplier/CLAUDE.md")
	if err != nil {
		t.Fatal(err)
	}
	model := evalEnv("SUPPLIER_EVAL_MODEL", "sonnet")
	runs := evalInt("SUPPLIER_EVAL_RUNS", 3)
	parallel := evalInt("SUPPLIER_EVAL_PARALLEL", 4)

	var cases []EvalCase
	only := strings.Split(evalEnv("SUPPLIER_EVAL_ONLY", ""), ",")
	for _, c := range loadEvalCases(t) {
		keep := evalEnv("SUPPLIER_EVAL_ONLY", "") == ""
		for _, o := range only {
			if o = strings.TrimSpace(o); o != "" && strings.Contains(c.Name, o) {
				keep = true
			}
		}
		if keep {
			cases = append(cases, c)
		}
	}
	t.Logf("model %s, %d case(s) x %d run(s), %d at a time", model, len(cases), runs, parallel)

	results := make([]evalResult, len(cases))
	for i, c := range cases {
		results[i] = evalResult{Case: c, Runs: make([]evalRun, runs)}
	}
	type job struct{ ci, ri int }
	jobs := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.ci].Runs[j.ri] = evalOnce(claude, model, string(instr), results[j.ci].Case)
			}
		}()
	}
	for ci := range cases {
		for ri := 0; ri < runs; ri++ {
			jobs <- job{ci, ri}
		}
	}
	close(jobs)
	wg.Wait()

	if p := evalEnv("SUPPLIER_EVAL_REPORT", ""); p != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Errorf("writing the report: %v", err)
		}
	}
	reportEval(t, results)
}

func evalOnce(claude, model, instr string, c EvalCase) evalRun {
	in := c.input()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, claude, ModelArgs(model, instr)...)
	cmd.Dir = os.TempDir()
	cmd.Stdin = strings.NewReader(Render(in, Config{}))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil || strings.TrimSpace(out.String()) == "" || looksLikeFailure(out.String()) {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String()) // claude reports some failures on stdout
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if err != nil {
			msg = err.Error() + " " + msg
		}
		d := Judge(nil, in, Config{})
		return evalRun{Raw: "error", Final: d.Verdict, Err: msg}
	}
	r := evalRun{Raw: "unparsable"}
	if res, err := ParseResult(out.Bytes()); err == nil {
		r.Raw, r.Why = res.Verdict, oneLine(res.Reason, 200)
	}
	d := Judge(out.Bytes(), in, Config{})
	r.Final = d.Verdict
	r.Notes = oneLine(strings.Join(d.Notes, "; "), 200)
	return r
}

// looksLikeFailure is true for claude's own error messages, which arrive on
// stdout: "Failed to authenticate..." must not be mistaken for an answer (it would
// parse as unparsable and count as Unsure, hiding the fault). A model reply that is
// merely not the expected JSON is NOT a failure: it is a result, counted as
// "unparsable" and as Unsure, because the lane would see exactly that.
func looksLikeFailure(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"failed to authenticate", "invalid api key", "api error", "error:", "oauth", "credit balance", "rate limit"} {
		if strings.HasPrefix(l, p) || (len(l) < 300 && strings.Contains(l, p)) {
			return true
		}
	}
	return false
}

func reportEval(t *testing.T, results []evalResult) {
	var (
		total, acceptable, exact, dangerous, errs, cautious, resolvable int
		byTag                                                           = map[string][2]int{} // tag -> {acceptable, total}
		gateMoves                                                       int
	)
	var lines []string
	firstErr := ""
	for _, r := range results {
		counts := map[string]int{}
		okN, exactN, dangN := 0, 0, 0
		for _, run := range r.Runs {
			total++
			counts[run.Final]++
			if run.Err != "" || run.Raw == "error" {
				errs++
				if firstErr == "" {
					firstErr = run.Err
				}
			}
			if r.Case.acceptable(run.Final) {
				okN++
				acceptable++
			}
			if run.Final == r.Case.Want {
				exactN++
				exact++
			}
			if run.Final == No && !r.Case.acceptable(No) {
				dangN++
				dangerous++
				t.Errorf("DANGEROUS %s: final No where %s is wanted. The model said %q: %s (code's notes: %s)",
					r.Case.Name, r.Case.Want, run.Raw, run.Why, run.Notes)
			}
			if run.Raw != run.Final && run.Raw != "error" && run.Raw != "unparsable" {
				gateMoves++
			}
			if r.Case.Want != Unsure {
				resolvable++
				if run.Final == Unsure {
					cautious++
				}
			}
		}
		for _, tg := range r.Case.Tags {
			v := byTag[tg]
			v[0] += okN
			v[1] += len(r.Runs)
			byTag[tg] = v
		}
		status := "ok"
		switch {
		case dangN > 0:
			status = "DANGEROUS"
		case okN < len(r.Runs):
			status = "miss"
		}
		var spread []string
		for _, v := range []string{Yes, No, Unsure} {
			if counts[v] > 0 {
				spread = append(spread, fmt.Sprintf("%s:%d", v, counts[v]))
			}
		}
		lines = append(lines, fmt.Sprintf("%-36s want %-6s got %-22s exact %d/%d  %s",
			r.Case.Name, r.Case.Want, strings.Join(spread, " "), exactN, len(r.Runs), status))
	}
	t.Log("\n" + strings.Join(lines, "\n"))

	var tagNames []string
	for k := range byTag {
		tagNames = append(tagNames, k)
	}
	sort.Strings(tagNames)
	var tl []string
	for _, k := range tagNames {
		tl = append(tl, fmt.Sprintf("%s %d/%d", k, byTag[k][0], byTag[k][1]))
	}
	t.Logf("\nacceptable %d/%d (%.0f%%)   exact %d/%d (%.0f%%)   DANGEROUS %d   model calls that failed %d",
		acceptable, total, pct(acceptable, total), exact, total, pct(exact, total), dangerous, errs)
	t.Logf("too cautious (Unsure where a Yes or No was wanted): %d/%d (%.0f%%)   answers code moved toward Unsure: %d",
		cautious, resolvable, pct(cautious, resolvable), gateMoves)
	t.Logf("by tag: %s", strings.Join(tl, "   "))
	if total > 0 && errs*2 > total {
		t.Fatalf("more than half the model calls failed (%d of %d), so these numbers mean nothing.\nThe first error was: %s\nCheck that claude is logged in (run `claude` once), ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN, and SUPPLIER_EVAL_MODEL.", errs, total, firstErr)
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
