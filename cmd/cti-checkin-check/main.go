// cti-checkin-check makes run-checkin's three file checks around a beat
// (internal/checkin/preflight.go). It reads and reports; it changes nothing.
//
//	cti-checkin-check --guard-wired checkin-settings.json --guard /opt/cti-agent/bin/checkin-bash-guard
//	cti-checkin-check --steering ~/.claude/settings.json ~/.claude.json
//	cti-checkin-check --tripped state/checkin-counts/<beat>.json
//
// --guard-wired exits 0 when the settings run the guard as the Bash
// PreToolUse hook with hooks on, and 1 when they do not: run-checkin refuses
// to start the beat. --steering prints one line per problem in Claude Code's
// own config files (nothing when they are clean). --tripped prints "limit
// reached for ..." when the guard enforced a limit during the beat, nothing
// when it did not, and exits 1 when the counter file cannot be read.
//
// It replaced three python3 heredocs in run-checkin; the rules are the same.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zany2dmax/cti-agent/internal/checkin"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = "usage: cti-checkin-check --guard-wired SETTINGS --guard PATH | --steering FILE... | --tripped COUNTS"

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cti-checkin-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wired := fs.String("guard-wired", "", "the beat's --settings file: does it run --guard as the Bash PreToolUse hook?")
	guard := fs.String("guard", "", "the guard's path on this box, as the settings must name it")
	steering := fs.Bool("steering", false, "audit the Claude Code config files named after the flags")
	tripped := fs.String("tripped", "", "the beat's counter file: which limits did the guard enforce?")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, on := range []bool{*wired != "", *steering, *tripped != ""} {
		if on {
			modes++
		}
	}
	if modes != 1 || (*wired != "") != (*guard != "") || (!*steering && fs.NArg() > 0) {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	switch {
	case *wired != "":
		// #nosec G304 -- the runner passes the root-owned settings file.
		raw, err := os.ReadFile(*wired)
		if err != nil || !checkin.GuardWired(raw, *guard) {
			return 1
		}
		return 0
	case *steering:
		for _, line := range checkin.SteeringProblems(fs.Args()) {
			_, _ = fmt.Fprintln(stdout, safelog.LineMax(line, 2000))
		}
		return 0
	default:
		line, err := checkin.Tripped(*tripped)
		if err != nil {
			return 1
		}
		if line != "" {
			_, _ = fmt.Fprintln(stdout, safelog.LineMax(line, 2000))
		}
		return 0
	}
}
