// Package cli is the one rule every fleet command that changes something
// follows: it has to be told how to run.
//
// A command that sends mail, moves mail, files tickets or changes another
// system takes exactly one of
//
//	--dry-run    do everything except the change, and say what it would do
//	--for-real   do it
//
// and some also --to-dev, a test send to FLEET_DEV_EMAIL only (which may be
// combined with --dry-run to rehearse that send). With none of them the
// command prints this usage and exits 2 without touching anything.
//
// There is deliberately no default. A default is a choice made for you and
// remembered by nobody: for years one command in this fleet rehearsed unless
// told otherwise and every other acted unless told otherwise, so the command
// an operator typed from habit did the opposite of what they meant. The same
// rule holds for a person, a systemd unit and the heartbeat agent, so a unit
// that loses its flag fails loudly instead of quietly doing nothing.
package cli

import (
	"fmt"
	"strings"
)

// Mode is how a command was told to run.
type Mode struct {
	DryRun  bool
	ForReal bool
	ToDev   bool
}

// Words says what each mode means for one command. Empty fields get a generic
// description.
type Words struct {
	DryRun  string
	ForReal string
	ToDev   string
}

// Resolve checks the three flags a command parsed and returns the mode, or a
// message ready to print to stderr (with the command's name) and exit 2.
//
// Legal: --dry-run, --for-real, --to-dev, or --to-dev with --dry-run. Anything
// else, including none, is refused. allowDev is false for a command that has
// no --to-dev, so it is not offered.
func Resolve(prog string, dry, real, dev, allowDev bool, w Words) (Mode, string) {
	m := Mode{DryRun: dry, ForReal: real, ToDev: dev}
	switch {
	case real && dry:
		return Mode{}, prog + ": --dry-run and --for-real contradict each other - say which one"
	case real && dev:
		return Mode{}, prog + ": --to-dev and --for-real contradict each other - a test send is not the real one"
	case dev && !allowDev:
		return Mode{}, prog + ": there is no --to-dev for this command\n" + usage(prog, false, w)
	case !dry && !real && !dev:
		return Mode{}, usage(prog, allowDev, w)
	}
	return m, ""
}

func usage(prog string, allowDev bool, w Words) string {
	or := func(s, d string) string {
		if s != "" {
			return s
		}
		return d
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: say how to run it - one of:\n", prog)
	fmt.Fprintf(&b, "  --dry-run   %s\n", or(w.DryRun, "do everything except the change, and show what it would do"))
	fmt.Fprintf(&b, "  --for-real  %s\n", or(w.ForReal, "do it"))
	if allowDev {
		fmt.Fprintf(&b, "  --to-dev    %s\n", or(w.ToDev, "test send to FLEET_DEV_EMAIL only"))
	}
	fmt.Fprintf(&b, "see: cti-agent %s --help", prog)
	return b.String()
}
