// cti-audit writes to the fleet's audit trail from a script, prunes it, and
// checks it. The Go commands write their own events through internal/audit;
// this is the same writer for the parts that are not Go (fleet-owners), plus
// the retention rule.
//
//	cti-audit --action jira.issue.create --target CR-100 --outcome success
//	cti-audit --prune --days 120            delete audit files older than that
//	cti-audit --prune --days 120 --dry-run  say which, delete nothing
//	cti-audit --check                       is the trail writable, and is the collector reachable
//
// The trail is RFC 5424 syslog lines in /var/log/cti-agent (AUDIT_DIR), one
// file per UTC day. See internal/audit for the format and what it does and
// does not prove. Nothing here knows which SIEM, if any, is on the other end
// of AUDIT_SYSLOG_ADDR.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/audit"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cti-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	action := fs.String("action", "", "event: what was done, e.g. owners.add (becomes the syslog MSGID)")
	target := fs.String("target", "", "event: what it was done to")
	outcome := fs.String("outcome", "", "event: success, failure or refused")
	detail := fs.String("detail", "", "event: a short safe note; never a body or a secret")
	lane := fs.String("lane", "", "event: the lane or command name (default cti-audit)")
	prune := fs.Bool("prune", false, "delete audit files older than --days")
	days := fs.Int("days", 0, "with --prune: how many days to keep (the cleanup passes AUDIT_RETAIN_DAYS, default 120)")
	dry := fs.Bool("dry-run", false, "with --prune: list what would be deleted, delete nothing")
	check := fs.Bool("check", false, "report whether the trail is writable and whether the collector (if any) is reachable; exit 1 if not")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fleetenv.Load()

	modes := 0
	for _, on := range []bool{*action != "", *prune, *check} {
		if on {
			modes++
		}
	}
	switch {
	case modes != 1:
		_, _ = fmt.Fprintln(stderr, "cti-audit: say what to do - one of --action (write an event), --prune, or --check. See: cti-agent cti-audit --help")
		return 2
	case *dry && !*prune:
		_, _ = fmt.Fprintln(stderr, "cti-audit: --dry-run goes with --prune")
		return 2
	case *days != 0 && !*prune:
		_, _ = fmt.Fprintln(stderr, "cti-audit: --days goes with --prune")
		return 2
	}

	l := audit.FromEnv()
	l.Warn = stderr
	switch {
	case *prune:
		return doPrune(l, *days, *dry, stdout, stderr)
	case *check:
		return doCheck(l, stdout)
	}

	o := strings.ToLower(strings.TrimSpace(*outcome))
	if o != audit.Success && o != audit.Failure && o != audit.Refused {
		_, _ = fmt.Fprintf(stderr, "cti-audit: --outcome must be %s, %s or %s\n", audit.Success, audit.Failure, audit.Refused)
		return 2
	}
	if *lane != "" {
		l.Lane = *lane
	}
	// A write problem is already reported on stderr by the logger; the caller
	// (a script mid-task) must not fail because of it.
	_ = l.Emit(audit.Event{Action: *action, Target: *target, Outcome: o, Detail: *detail})
	return 0
}

func doPrune(l *audit.Logger, days int, dry bool, stdout, stderr io.Writer) int {
	if days < 1 {
		_, _ = fmt.Fprintln(stderr, "cti-audit: --prune needs --days N (1 or more)")
		return 2
	}
	dir := dirOf(l)
	if dir == "off" {
		_, _ = fmt.Fprintln(stdout, "cti-audit: AUDIT_DIR=off, nothing to prune")
		return 0
	}
	gone, err := audit.Prune(dir, days, time.Now(), dry)
	verb := "deleted"
	if dry {
		verb = "would delete"
	}
	for _, n := range gone {
		_, _ = fmt.Fprintf(stdout, "cti-audit: %s %s\n", verb, filepath.Join(dir, n))
	}
	_, _ = fmt.Fprintf(stdout, "cti-audit: %s %d audit file(s) older than %d days in %s\n", verb, len(gone), days, dir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cti-audit: %v\n", err)
		return 1
	}
	return 0
}

func dirOf(l *audit.Logger) string {
	if l.Dir == "" {
		return audit.DefaultDir
	}
	return l.Dir
}

func doCheck(l *audit.Logger, stdout io.Writer) int {
	bad := 0
	say := func(ok bool, format string, a ...any) {
		tag := "ok   "
		if !ok {
			tag = "FAIL "
			bad++
		}
		_, _ = fmt.Fprintf(stdout, "%s"+format+"\n", append([]any{tag}, a...)...)
	}
	dir := dirOf(l)
	switch {
	case dir == "off":
		say(false, "AUDIT_DIR=off: audit events are being discarded")
	default:
		fi, err := os.Stat(dir)
		switch {
		case err != nil:
			say(false, "%s: %v (events go to stderr, i.e. the journal, until it exists)", dir, err)
		case !fi.IsDir():
			say(false, "%s is not a directory", dir)
		default:
			probe := filepath.Join(dir, ".check-"+strconv.Itoa(os.Getpid()))
			f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- inside our own audit directory
			if err != nil {
				say(false, "%s is not writable by this user: %v", dir, err)
			} else {
				_ = f.Close()
				_ = os.Remove(probe)
				say(true, "%s is writable (mode %v)", dir, fi.Mode().Perm())
			}
		}
	}
	if l.Forward == nil {
		_, _ = fmt.Fprintln(stdout, "ok    forwarding is off (AUDIT_SYSLOG_ADDR unset): the files are the trail")
	} else {
		proto := l.Forward.Proto
		if proto == "" {
			proto = "tls"
		}
		if err := l.Forward.Probe(); err != nil {
			say(false, "collector %s over %s: %v", l.Forward.Addr, proto, err)
		} else {
			say(true, "collector %s over %s is reachable", l.Forward.Addr, proto)
		}
		if proto != "tls" {
			_, _ = fmt.Fprintf(stdout, "warn  %s sends audit lines unencrypted; tls is the default\n", proto)
		}
	}
	if bad > 0 {
		return 1
	}
	return 0
}
