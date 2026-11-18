// cti-falcon checks the fleet's CrowdStrike Falcon API client.
//
//	cti-falcon --check           # token, then one read per scope
//	cti-falcon --check --json    # the same as JSON
//
// # WHAT IT IS FOR
//
// Advisory triage will read three things from Falcon: the applications we run
// (Assets), which hosts saw an indicator (IOC Management), and which ATT&CK
// techniques our detections fired on (Alerts), plus host details (Hosts).
// Before any of that is built, --check proves the API client works: the base
// URL is the right cloud, the credentials give a token, and each of the four
// Read scopes answers on the exact route the triage will call. A 403 on
// Assets usually means Falcon Discover is not licensed, which decides where
// the inventory comes from.
//
// It reads with limit=1 and prints counts at most. It never prints the token,
// the secret, an ID or a record, and it revokes its token before it exits.
//
// # SETTINGS
//
// FALCON_BASE_URL, FALCON_CLIENT_ID and FALCON_CLIENT_SECRET, from the
// environment or fleet.env. There is deliberately no flag for the secret: a
// flag lands in shell history and the process list.
//
// Exit 0 when the token and every scope work, 1 when anything fails, 2 on
// bad usage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/zany2dmax/cti-agent/internal/falcon"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
)

const (
	exitOK    = 0
	exitErr   = 1
	exitUsage = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// newClient is a seam so the entry point can be tested without Falcon.
var newClient = falcon.New

type report struct {
	Host     string               `json:"host"`
	Region   string               `json:"region"`
	Token    string               `json:"token"`
	TokenErr string               `json:"token_error,omitempty"`
	Scopes   []falcon.ProbeResult `json:"scopes"`
	OK       bool                 `json:"ok"`
}

func run(args []string, stdout, stderr io.Writer) int {
	fleetenv.Load()
	fs := flag.NewFlagSet("cti-falcon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "get a token and run one read per scope; prints counts only")
	asJSON := fs.Bool("json", false, "with --check: print the result as JSON")
	timeout := fs.Duration("timeout", 2*time.Minute, "give up after this long")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: cti-falcon --check [--json] [--timeout DURATION]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if !*check || fs.NArg() > 0 {
		fs.Usage()
		return exitUsage
	}
	logf := func(format string, a ...any) { _, _ = fmt.Fprintf(stderr, "[falcon] "+format+"\n", a...) }

	c, err := newClient(os.Getenv("FALCON_BASE_URL"), os.Getenv("FALCON_CLIENT_ID"), os.Getenv("FALCON_CLIENT_SECRET"))
	if err != nil {
		logf("error  : %v", err)
		logf("set FALCON_BASE_URL, FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in fleet.env (RUNBOOK: the CrowdStrike API client)")
		return exitErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rep := report{Host: c.Host(), Region: c.Region()}

	exp, err := c.Token(ctx)
	if err != nil {
		rep.Token, rep.TokenErr = "failed", err.Error()
	} else {
		rep.Token = "ok"
		for _, p := range falcon.Probes {
			rep.Scopes = append(rep.Scopes, c.RunProbe(ctx, p))
		}
		// A fresh context: the probes may have used up the main one, and
		// the token should not be left live either way.
		rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := c.Revoke(rctx); err != nil {
			logf("warn   : %v (the token expires on its own at %s)", err, exp.Format(time.RFC3339))
		}
		rcancel()
	}
	rep.OK = rep.Token == "ok" && len(rep.Scopes) == len(falcon.Probes)
	for _, s := range rep.Scopes {
		if s.Result != falcon.ProbeOK {
			rep.OK = false
		}
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return exitErr
		}
	} else {
		printText(stdout, rep)
	}
	if !rep.OK {
		return exitErr
	}
	return exitOK
}

func printText(w io.Writer, rep report) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("cloud  : %s (%s)", rep.Host, rep.Region)
	if rep.Token != "ok" {
		p("token  : FAILED - %s", rep.TokenErr)
		p("result : no scope was checked")
		return
	}
	p("token  : ok")
	ok := 0
	for _, s := range rep.Scopes {
		line := fmt.Sprintf("%-22s %-7s %s", s.Scope, upper(s.Result), s.What)
		if s.Total != nil {
			line += fmt.Sprintf(" (%d in total)", *s.Total)
		}
		p("%s", line)
		if s.Detail != "" {
			p("%22s   %s", "", s.Detail)
		}
		if s.Result == falcon.ProbeOK {
			ok++
		}
	}
	p("result : %d of %d scopes work", ok, len(falcon.Probes))
}

func upper(s string) string {
	switch s {
	case falcon.ProbeOK:
		return "OK"
	case falcon.ProbeDenied:
		return "DENIED"
	}
	return "ERROR"
}
