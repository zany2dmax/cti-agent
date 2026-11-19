// cti-checkin-verdict checks the cti-checkin/1 verdict a check-in beat ends
// with (HARNESS.md, H3), against the counts checkin-bash-guard kept for it.
//
//	cti-checkin-verdict --trace state/traces/checkin-<ts>.jsonl --counts state/checkin-counts/<beat>.json
//	cti-checkin-verdict --text beat.log --out state/verdicts/checkin-<beat>.json
//
// run-checkin calls it after every beat that exited 0. It reads the beat's
// final message (the trace's result event, or a plain-text log), finds the
// verdict, checks it against the schema and the guard's counts, and prints one
// line: "verdict: valid - ..." or "verdict: KIND[,KIND] - problem; problem".
// --out saves the verdict and every problem as JSON (0600) for the evals and
// later tools.
//
// Exit 0 for a valid verdict, 1 for any problem (MISSING, INVALID, MISMATCH),
// 2 when it could not read its input. It sends nothing and changes nothing but
// --out: what to do about a bad verdict is the runner's decision.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/checkin"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

func main() { os.Exit(run()) }

func run() int {
	trace := flag.String("trace", "", "the beat's fleet-trace file: the verdict is read from its result event")
	text := flag.String("text", "", "the beat's plain-text output, for a beat run without a trace")
	counts := flag.String("counts", "", "checkin-bash-guard's counter file for the beat; without it the counts are not checked")
	out := flag.String("out", "", "also save the verdict and its problems here as JSON (0600)")
	beat := flag.String("beat", "", "the beat id, recorded in --out")
	asJSON := flag.Bool("json", false, "print the full result as JSON instead of one line")
	flag.Parse()

	if (*trace == "") == (*text == "") {
		fmt.Fprintln(os.Stderr, "cti-checkin-verdict: give exactly one of --trace or --text")
		return 2
	}
	final, err := finalMessage(*trace, *text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cti-checkin-verdict: %s\n", safelog.Line(err.Error()))
		return 2
	}
	var c *checkin.Counts
	if *counts != "" {
		if c, err = checkin.LoadCounts(*counts); err != nil {
			fmt.Fprintf(os.Stderr, "cti-checkin-verdict: counts unreadable, not checked: %s\n", safelog.Line(err.Error()))
			c = nil
		}
	}
	res := checkin.Evaluate(final, c)
	res.Beat = *beat

	if *out != "" {
		if err := save(*out, res); err != nil {
			fmt.Fprintf(os.Stderr, "cti-checkin-verdict: %s\n", safelog.Line(err.Error()))
		}
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println(safelog.LineMax(summary(res, c != nil), 900))
	}
	if !res.Valid {
		return 1
	}
	return 0
}

// finalMessage is the beat's last words: the trace's result event, or the
// whole plain-text log (the verdict is the last object in either).
func finalMessage(trace, text string) (string, error) {
	if text != "" {
		// #nosec G304 -- the runner passes the beat's own log.
		b, err := os.ReadFile(text)
		return string(b), err
	}
	// #nosec G304 -- the runner passes the beat's own trace.
	f, err := os.Open(trace)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	final := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		var ev struct {
			Type   string `json:"type"`
			Result string `json:"result"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Type == "result" {
			final = ev.Result
		}
	}
	return final, sc.Err()
}

func summary(r checkin.Result, counted bool) string {
	if r.Valid {
		v := r.Verdict
		against := "the guard's counts"
		if !counted {
			against = "the schema only (no counts)"
		}
		return fmt.Sprintf("verdict: valid - status %s, %d lanes, %d escalation(s), checked against %s",
			v.Status, len(v.Lanes), len(v.Escalations), against)
	}
	parts := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		parts = append(parts, p.Text)
	}
	return "verdict: " + strings.Join(r.Kinds(), ",") + " - " + strings.Join(parts, "; ")
}

func save(path string, r checkin.Result) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// #nosec G304 G306 -- the runner's own state directory; 0600 on purpose.
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
