// cti-falcon checks the fleet's CrowdStrike Falcon API client.
//
//	cti-falcon --check                     # token, then one read per scope
//	cti-falcon --find-app chrome           # do we run it? hosts, versions
//	cti-falcon --find-app "Google Chrome" --exact --vendor "Google LLC"
//	cti-falcon --new-apps 7                # apps first seen this week that we never had
//	add --json to any of them for JSON
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
// --check reads with limit=1 and prints counts at most. --find-app and
// --new-apps print application names, versions and host counts, never a host
// name or ID. Every mode revokes its token before it exits.
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
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/falcon"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/safelog"
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
	findApp := fs.String("find-app", "", "list installed applications whose name contains this, with host counts")
	vendor := fs.String("vendor", "", "with --find-app: the vendor must contain this too")
	exact := fs.Bool("exact", false, "with --find-app: name and vendor must match exactly, not contain")
	newApps := fs.Int("new-apps", 0, "list applications first seen in the last N days that the estate never had before")
	maxRows := fs.Int("max-rows", 0, "stop reading after this many records (default 2000 for --find-app, 10000 for --new-apps)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	timeout := fs.Duration("timeout", 2*time.Minute, "give up after this long (--new-apps: at least 15m)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: cti-falcon --check | --find-app NAME [--vendor V] [--exact] | --new-apps DAYS  [--json] [--max-rows N] [--timeout D]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	modes := 0
	for _, on := range []bool{*check, *findApp != "", *newApps != 0} {
		if on {
			modes++
		}
	}
	if modes != 1 || fs.NArg() > 0 || *newApps < 0 || *newApps > 90 || *maxRows < 0 ||
		((*vendor != "" || *exact) && *findApp == "") {
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

	if *findApp != "" || *newApps != 0 {
		d := *timeout
		if *newApps != 0 && d < 15*time.Minute {
			d = 15 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		defer revoke(c, logf)
		if *findApp != "" {
			return findApps(ctx, c, *findApp, falcon.FindOpts{Vendor: *vendor, Exact: *exact, MaxRows: *maxRows}, *asJSON, stdout, logf)
		}
		return listNewApps(ctx, c, *newApps, *maxRows, *asJSON, stdout, logf)
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

func revoke(c *falcon.Client, logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Revoke(ctx); err != nil {
		logf("warn   : %v (the token expires on its own)", err)
	}
}

func writeJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return exitErr
	}
	return exitOK
}

func findApps(ctx context.Context, c *falcon.Client, name string, o falcon.FindOpts, asJSON bool, w io.Writer, logf func(string, ...any)) int {
	res, err := c.FindApps(ctx, name, o)
	if err != nil {
		logf("error  : %v", err)
		return exitErr
	}
	if asJSON {
		return writeJSON(w, res)
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("filter : %s", res.Filter)
	capped := ""
	if res.Truncated {
		capped = fmt.Sprintf(" - read the first %d, so host counts below are a lower bound (raise --max-rows)", res.Read)
	}
	p("matched: %d records%s", res.Total, capped)
	if len(res.Apps) == 0 {
		p("no installed application matched")
		return exitOK
	}
	for _, a := range res.Apps {
		printApp(w, a, "")
	}
	return exitOK
}

func listNewApps(ctx context.Context, c *falcon.Client, days, maxRows int, asJSON bool, w io.Writer, logf func(string, ...any)) int {
	since := now().Add(-time.Duration(days) * 24 * time.Hour)
	rep, err := c.NewApps(ctx, since, falcon.NewAppsOpts{MaxRows: maxRows})
	if err != nil {
		logf("error  : %v", err)
		return exitErr
	}
	if asJSON {
		return writeJSON(w, rep)
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("window : since %s (%d days)", rep.Since.Format(time.RFC3339), days)
	capped := ""
	if rep.Truncated {
		capped = fmt.Sprintf(" - read the first %d only (raise --max-rows)", rep.Read)
	}
	p("records: %d first seen in the window%s", rep.Total, capped)
	p("new to the estate: %d", len(rep.New))
	for _, a := range rep.New {
		printApp(w, a.AppSummary, "  ")
	}
	if len(rep.NotChecked) > 0 {
		p("not checked: %d (a name a lookup cannot use, or over the check cap) - treat as possibly new", len(rep.NotChecked))
		for _, a := range rep.NotChecked {
			printApp(w, a.AppSummary, "  ")
		}
	}
	p("seen before: %d applications (updates, or new hosts for something we already run)", rep.SeenBefore)
	return exitOK
}

// now is a seam for --new-apps' window.
var now = time.Now

func printApp(w io.Writer, a falcon.AppSummary, indent string) {
	// Names come from Discover, and anyone who can install software on an
	// endpoint chooses them: no control character reaches the terminal.
	name := safelog.LineMax(a.Name, 120)
	if a.Vendor != "" {
		name = safelog.LineMax(a.Vendor, 80) + " / " + name
	}
	extra := ""
	if a.NoHost > 0 {
		extra = fmt.Sprintf(", plus %d record(s) naming no host", a.NoHost)
	}
	_, _ = fmt.Fprintf(w, "%s%s - %d host(s)%s\n", indent, name, a.Hosts, extra)
	_, _ = fmt.Fprintf(w, "%s    versions : %s\n", indent, top(a.Versions, 5))
	_, _ = fmt.Fprintf(w, "%s    platforms: %s\n", indent, top(a.Platforms, 5))
}

// top prints the n largest entries of a count map, "value (count)".
func top(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	xs := make([]kv, 0, len(m))
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].v != xs[j].v {
			return xs[i].v > xs[j].v
		}
		return xs[i].k < xs[j].k
	})
	parts := []string{}
	for i, x := range xs {
		if i == n {
			parts = append(parts, fmt.Sprintf("+%d more", len(xs)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", safelog.LineMax(x.k, 60), x.v))
	}
	return strings.Join(parts, ", ")
}
