// cti-budget rations the heartbeat's share of a Claude subscription.
//
// The fleet and its operator draw on the same quota, on different machines,
// with no API that reports what is left. So the fleet limits itself and
// leaves the remainder alone.
//
//	cti-budget check                     exit 0 to proceed, 3 to skip
//	cti-budget record --outcome ok       after a beat
//	cti-budget record --exit 1 --output "$err"   let it classify
//	cti-budget status                    what it would do and why
//
// Exit codes are the interface, because the caller is a shell script:
//
//	0  allowed, or the command succeeded
//	1  operational failure (unreadable ledger, bad flags)
//	3  denied - skip this beat. Distinct from 1 so that a skipped beat is
//	   not reported as a broken one; systemd would mark the unit failed and
//	   cti-alert would email about a working brake.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/zany2dmax/cti-agent/internal/budget"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitDenied  = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: cti-budget <check|record|status> [flags]")
		return exitFailure
	}
	switch args[0] {
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "record":
		return cmdRecord(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "cti-budget: unknown command %q\n", args[0])
		return exitFailure
	}
}

// storeFromEnv builds the store from fleet.env, so the ceilings are tunable
// without a rebuild. Every knob has a working default; an operator who sets
// nothing gets the shipped two-hour-cadence budget.
func storeFromEnv() *budget.Store {
	home := os.Getenv("FLEET_HOME")
	if home == "" {
		home = "."
	}
	lim := budget.DefaultLimits()
	lim.Window = envDuration("FLEET_BUDGET_WINDOW_HOURS", lim.Window)
	lim.WindowBeats = envInt("FLEET_BUDGET_WINDOW_BEATS", lim.WindowBeats)
	lim.DailyBeats = envInt("FLEET_BUDGET_DAILY_BEATS", lim.DailyBeats)
	lim.BackoffBase = envDuration("FLEET_BUDGET_BACKOFF_BASE_HOURS", lim.BackoffBase)
	lim.BackoffMax = envDuration("FLEET_BUDGET_BACKOFF_MAX_HOURS", lim.BackoffMax)

	path := os.Getenv("FLEET_BUDGET_FILE")
	if path == "" {
		path = filepath.Join(home, "budget.json")
	}
	return budget.NewStore(path, lim)
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		_, _ = fmt.Fprintf(os.Stderr, "cti-budget: ignoring %s=%q, want a positive integer\n", key, v)
	}
	return def
}

// envDuration takes hours, possibly fractional, because "0.5" is a friendlier
// thing to write in fleet.env than a Go duration string.
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return time.Duration(f * float64(time.Hour))
		}
		_, _ = fmt.Fprintf(os.Stderr, "cti-budget: ignoring %s=%q, want hours as a number\n", key, v)
	}
	return def
}

func cmdCheck(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	quiet := fs.Bool("quiet", false, "print nothing when allowed")
	alertFlag := fs.Bool("print-alert-flag", false,
		"on denial, print 'alert' or 'silent' as the last line, so the caller "+
			"can decide whether to escalate without re-reading the ledger")
	if err := fs.Parse(args); err != nil {
		return exitFailure
	}

	s := storeFromEnv()
	l, err := s.Load()
	if err != nil {
		// A corrupt ledger returns an empty one plus an error. Warn and carry
		// on: failing closed here would stop the heartbeat over a counter.
		_, _ = fmt.Fprintf(stderr, "cti-budget: %v\n", err)
	}

	d := s.Check(l)
	if d.Allow {
		if !*quiet {
			_, _ = fmt.Fprintf(stdout, "budget ok: %s\n", d.Reason)
		}
		return exitOK
	}

	_, _ = fmt.Fprintf(stdout, "budget denied: %s\n", d.Reason)
	if !d.RetryAfter.IsZero() {
		_, _ = fmt.Fprintf(stdout, "next attempt viable after %s\n", d.RetryAfter.Format(time.RFC3339))
	}
	if *alertFlag {
		should := s.ShouldAlert(l, d)
		// ShouldAlert mutates the ledger, so it has to be persisted or every
		// denial would alert again.
		if err := s.Save(l); err != nil {
			_, _ = fmt.Fprintf(stderr, "cti-budget: could not persist alert state: %v\n", err)
		}
		// This one write is checked rather than discarded. run-checkin reads
		// the word on stdout to decide whether to raise an alert, so losing it
		// is not a cosmetic failure: an empty read looks exactly like
		// "silent", and the alert that should have fired would not. Everything
		// else this command prints is advisory and the exit code carries the
		// decision, but this line IS the decision.
		// alertWord, not "flag": this function calls flag.NewFlagSet above, and
		// a local named flag shadows the package for the rest of the block.
		alertWord := "silent"
		if should {
			alertWord = "alert"
		}
		if _, err := fmt.Fprintln(stdout, alertWord); err != nil {
			// Report it, but still return exitDenied. run-checkin treats any
			// code other than 3 as "the check itself failed, proceed with the
			// beat" - so returning a usage or error code here would defeat the
			// rate limiter in order to complain about a lost print. The brake
			// matters more than the alert. run-checkin folds stderr into the
			// text it posts to the board, so the lost flag is visible there.
			_, _ = fmt.Fprintf(stderr,
				"cti-budget: DENIED but could not write the alert flag (%q) to "+
					"stdout: %v - no alert will be raised for this denial\n",
				alertWord, err)
		}
	}
	return exitDenied
}

func cmdRecord(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	outcome := fs.String("outcome", "", "ok|ratelimit|error; omit to classify from --exit and --output")
	exitCode := fs.Int("exit", 0, "exit status of the claude invocation")
	output := fs.String("output", "", "stderr/stdout of the invocation, used to classify")
	note := fs.String("note", "", "short free-text note stored with the beat")
	if err := fs.Parse(args); err != nil {
		return exitFailure
	}

	var o budget.Outcome
	switch *outcome {
	case "":
		o = budget.Classify(*exitCode, *output)
	case string(budget.OutcomeOK), string(budget.OutcomeRateLimit), string(budget.OutcomeError):
		o = budget.Outcome(*outcome)
	default:
		_, _ = fmt.Fprintf(stderr, "cti-budget: --outcome must be ok, ratelimit or error\n")
		return exitFailure
	}

	s := storeFromEnv()
	l, err := s.Load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cti-budget: %v\n", err)
	}
	s.Record(l, o, *note)
	if err := s.Save(l); err != nil {
		_, _ = fmt.Fprintf(stderr, "cti-budget: %v\n", err)
		return exitFailure
	}

	_, _ = fmt.Fprintf(stdout, "recorded %s\n", o)
	if o == budget.OutcomeRateLimit {
		_, _ = fmt.Fprintf(stdout, "cooling off until %s\n", l.CooldownUntil.Format(time.RFC3339))
	}
	return exitOK
}

func cmdStatus(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable")
	if err := fs.Parse(args); err != nil {
		return exitFailure
	}

	s := storeFromEnv()
	l, err := s.Load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cti-budget: %v\n", err)
	}
	d := s.Check(l)

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ledger":       s.Path,
			"allow":        d.Allow,
			"reason":       d.Reason,
			"retry_after":  d.RetryAfter,
			"beats_stored": len(l.Beats),
			"limits": map[string]any{
				"window_hours": s.Limits.Window.Hours(),
				"window_beats": s.Limits.WindowBeats,
				"daily_beats":  s.Limits.DailyBeats,
			},
		})
		return exitOK
	}

	_, _ = fmt.Fprintf(stdout, "ledger:  %s\n", s.Path)
	_, _ = fmt.Fprintf(stdout, "limits:  %d beats per %s, %d per day\n",
		s.Limits.WindowBeats, s.Limits.Window, s.Limits.DailyBeats)
	_, _ = fmt.Fprintf(stdout, "beats:   %d recorded in the last 48h\n", len(l.Beats))
	if d.Allow {
		_, _ = fmt.Fprintf(stdout, "state:   ready (%s)\n", d.Reason)
	} else {
		_, _ = fmt.Fprintf(stdout, "state:   holding - %s\n", d.Reason)
	}
	return exitOK
}
