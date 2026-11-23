// cti-sanitize cleans text before the orchestrator's model reads it
// (PrimeSec design review 39260, Scenario-222).
//
//	some-command | cti-sanitize --source NAME
//
// It is a filter, not an operator command. The heartbeat's wrappers
// (fleet-board, fleet-journal, fleet-db) pipe their output through it only
// inside a beat (CHECKIN_BEAT_ID set, by run-checkin), so a lane that parses
// the same command's output is unaffected. If it cannot run, the wrapper
// prints nothing: raw output is not an option inside a beat.
//
// What it removes and cuts, and what it logs, is internal/sanitize: the same
// package cti-alert, cti-kev, cti-mailbox and cti-patchtuesday clean their
// own output with. It replaced the Python fleet-sanitize, which kept a second
// copy of those rules.
//
// It never writes to stderr except for a usage error, because stderr goes
// back into the model. Every line it changes is logged to the journal under
// the cti-sanitize tag.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/sanitize"
)

// maxInput bounds what is held in memory. The output is cut at
// sanitize.MaxTotal (64 KB) anyway; past this the rest of stdin is read and
// thrown away, so the command feeding the pipe is never left blocked.
const maxInput = 16 << 20

const usage = "usage: cti-sanitize [--source NAME]   (reads stdin)"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, sanitize.Log))
}

func run(args []string, in io.Reader, out, errOut io.Writer, logf func(string, []sanitize.Event)) int {
	fs := flag.NewFlagSet("cti-sanitize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("source", "unknown", "a label for the journal lines")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, usage)
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxInput))
	if err != nil {
		return 1 // nothing on stderr: the wrapper prints nothing when this fails
	}
	_, _ = io.Copy(io.Discard, in)
	clean, events := sanitize.Text(string(raw))
	logf(sourceName(*source), events)
	if _, err := io.WriteString(out, clean); err != nil {
		return 1
	}
	return 0
}

// sourceName keeps the journal tag to ASCII letters, digits, dash,
// underscore and dot, at most 40 characters, so a caller cannot forge a log
// line through it.
func sourceName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 40 {
			break
		}
		if r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
