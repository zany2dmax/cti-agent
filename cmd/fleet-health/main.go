// fleet-health reads the lanes' health reports (internal/health) for the
// check-in, and for a person.
//
//	fleet-health delta --pending FILE   the beat's LANE HEALTH block: what changed
//	                                    since the last beat; the next state to FILE
//	fleet-health commit --pending FILE  save that state, once the beat has finished
//	fleet-health show                   every lane's report, one line each
//
// run-checkin runs delta before the beat and commit after a beat that
// finished, so each change reaches the model once and a quiet day costs one
// line. It reads only the fleet's own files: the reports under
// $FLEET_HOME/reports/health, the lane list ($FLEET_CODE/share/health.list,
// from the lane manifests), FLEET_LANES, and its state file
// ($FLEET_HOME/state/health-seen.json). It sends and changes nothing else.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/health"
	"github.com/zany2dmax/cti-agent/internal/layout"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now())) }

func usage(w io.Writer) int {
	_, _ = fmt.Fprintln(w, "usage: fleet-health delta --pending FILE | commit --pending FILE | show")
	return 2
}

func run(args []string, out, errw io.Writer, now time.Time) int {
	if len(args) == 0 {
		return usage(errw)
	}
	fs := flag.NewFlagSet("fleet-health "+args[0], flag.ContinueOnError)
	fs.SetOutput(errw)
	home := fs.String("home", envOr("FLEET_HOME", layout.StateDir), "the fleet's home: reports/health and state/ under it")
	list := fs.String("list", filepath.Join(envOr("FLEET_CODE", layout.CodeDir), "share", "health.list"),
		"the lanes' health contracts, generated from the lane manifests")
	state := fs.String("state", "", "the state file (default HOME/state/health-seen.json)")
	pending := fs.String("pending", "", "delta: write the next state here; commit: the state to save")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return usage(errw)
	}
	if *state == "" {
		*state = filepath.Join(*home, "state", "health-seen.json")
	}
	die := func(f string, a ...any) int {
		_, _ = fmt.Fprintf(errw, "fleet-health: %s\n", safelog.Line(fmt.Sprintf(f, a...)))
		return 1
	}
	switch args[0] {
	case "delta", "show":
		specs, err := loadSpecs(*list)
		if err != nil {
			return die("%s", err)
		}
		if args[0] == "show" {
			return show(out, specs, *home, now)
		}
		if *pending == "" {
			return usage(errw)
		}
		st, err := health.LoadState(*state)
		if err != nil {
			// A damaged state is a fresh start: every open gap is told again,
			// which is the safe direction.
			_, _ = fmt.Fprintf(errw, "fleet-health: state unreadable, starting afresh: %s\n", safelog.Line(err.Error()))
		}
		lines, next := health.Delta(specs, inUse(os.Getenv("FLEET_LANES")), *home, st, now)
		if err := writeState(*pending, next); err != nil {
			return die("%s", err)
		}
		_, _ = fmt.Fprintln(out, health.Block(lines))
		return 0
	case "commit":
		if *pending == "" {
			return usage(errw)
		}
		// #nosec G703 -- run-checkin's own state path
		if err := os.MkdirAll(filepath.Dir(*state), 0o700); err != nil {
			return die("%s", err)
		}
		// #nosec G703 -- run-checkin's own state paths
		if err := os.Rename(*pending, *state); err != nil {
			return die("%s", err)
		}
		return 0
	}
	return usage(errw)
}

func show(out io.Writer, specs []health.Spec, home string, now time.Time) int {
	for _, sp := range specs {
		r, err := health.Read(health.Path(home, sp.Lane))
		switch {
		case errors.Is(err, os.ErrNotExist):
			_, _ = fmt.Fprintf(out, "%-14s no report (cti-agent-%s.service has not written one)\n", sp.Lane, sp.Unit)
		case err != nil:
			_, _ = fmt.Fprintf(out, "%-14s unreadable: %s\n", sp.Lane, safelog.Line(err.Error()))
		case r.Error != "":
			_, _ = fmt.Fprintf(out, "%-14s error: %s\n", sp.Lane, safelog.Line(r.Error))
		default:
			age := now.Sub(r.Generated).Round(time.Minute)
			stale := ""
			if age > time.Duration(sp.FreshHours)*time.Hour {
				stale = " STALE"
			}
			_, _ = fmt.Fprintf(out, "%-14s %d of %d covered, %d unexpected gap(s), %d by design - %s old%s\n",
				sp.Lane, r.Covered, r.Of, len(r.Unexpected()), len(r.Gaps)-len(r.Unexpected()), age, stale)
		}
	}
	return 0
}

func loadSpecs(path string) ([]health.Spec, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- the installed lane list
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return health.ParseSpecs(f)
}

func inUse(lanes string) func(string) bool {
	set := map[string]bool{}
	for _, l := range strings.Split(strings.ReplaceAll(lanes, " ", ""), ",") {
		if l != "" {
			set[l] = true
		}
	}
	return func(l string) bool { return len(set) == 0 || set[l] }
}

func writeState(path string, st health.State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// #nosec G703 -- run-checkin's own state path
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600) // #nosec G703 -- as above
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
