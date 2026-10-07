// cti-domains is the weekly check of the organisation's domains.
//
//	cti-domains --out r.html --text-out r.txt --subject-out r.subject
//	cti-domains --no-registrar               # DNS and web only
//	cti-domains --no-state-write             # dry run: do not advance the diff
//
// For every domain in the inventory file: is it registered in the GoDaddy
// account (and is the account holding domains the file does not list), is it
// live or parked, does its certificate verify, and do its mail records match
// what the file says it does - a sending domain needs SPF, DKIM and an
// enforcing DMARC; a domain that does not send must say so in DNS so nobody
// else can send as it. Then what changed since last week.
//
// # IT DOES NOT SEND, AND IT ONLY READS
//
// Sending is cti-mailer's (--lane dom, DOM_TO against DOM_ALLOW_TO). The
// GoDaddy token is read-only and the client never requests auth codes. DNS
// and web probes are ordinary lookups and GETs of the domains we own.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/domains"
	"github.com/zany2dmax/cti-agent/internal/domains/godaddy"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() { os.Exit(run()) }

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "[domains] "+format+"\n", a...) }

func die(format string, a ...any) int {
	logf("error  : "+format, a...)
	return exitErr
}

// registrarFor is a seam so the entry point can be tested without GoDaddy.
var registrarFor = func(token string) domains.Registrar { return godaddy.New(token) }

// resolver and webProber are seams for the same reason.
var (
	resolver  domains.Resolver
	webProber domains.WebProber
)

func defaultState() string {
	home := os.Getenv("FLEET_HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, "state", "domains-state.json")
}

func defaultInventory() string {
	if s := strings.TrimSpace(os.Getenv("DOMAINS_FILE")); s != "" {
		return s
	}
	return "/etc/cti-agent/domains.txt"
}

func run() int {
	// Before flag defaults are computed, so DOMAINS_FILE and FLEET_HOME from
	// fleet.env apply to a run by hand exactly as they do under systemd.
	fleetenv.Load()

	inventory := flag.String("inventory", defaultInventory(), "the domain list (one per line, \"send\" marks a sender)")
	statePath := flag.String("state", defaultState(), "last week's observations, for the diff")
	noStateWrite := flag.Bool("no-state-write", false, "read last week's state but do not replace it (dry runs)")
	out := flag.String("out", "", "write the HTML here")
	textOut := flag.String("text-out", "", "write the plain-text version here")
	subjectOut := flag.String("subject-out", "", "write the subject line here (so the runner need not probe twice)")
	noRegistrar := flag.Bool("no-registrar", false, "skip GoDaddy; DNS and web checks only")
	concurrency := flag.Int("concurrency", 8, "domains probed at once")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request web timeout")
	flag.Parse()

	f, err := os.Open(*inventory)
	if err != nil {
		return die("cannot read the inventory %s: %s - it lives outside the repository "+
			"(see RUNBOOK); create it with one domain per line", safelog.Line(*inventory), safelog.Line(err.Error()))
	}
	entries, problems, err := domains.ParseInventory(f)
	_ = f.Close()
	if err != nil {
		return die("reading %s: %s", safelog.Line(*inventory), safelog.Line(err.Error()))
	}
	for _, p := range problems {
		logf("warn   : %s", safelog.Line(p))
	}
	if len(entries) == 0 {
		// A report on zero domains would arrive saying "no issues".
		return die("%s lists no domains - refusing to report on nothing", safelog.Line(*inventory))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	opt := domains.Options{Now: time.Now(), ExpectRUA: strings.TrimSpace(os.Getenv("DOMAINS_DMARC_RUA"))}
	var cmp *domains.Comparison
	var regs []domains.Registration
	orgOf := map[string]domains.Registration{}
	if *noRegistrar {
		logf("note   : --no-registrar - registration, expiry and account checks skipped")
	} else if tok := strings.TrimSpace(os.Getenv("GODADDY_PAT")); tok == "" {
		opt.RegistrarErr = "GODADDY_PAT is not set in fleet.env"
		logf("warn   : %s - registrar checks skipped", opt.RegistrarErr)
	} else {
		reg := registrarFor(tok)
		list, err := reg.Domains(ctx)
		if err != nil {
			// Not fatal. DNS and mail posture are most of the report; the
			// subject says the registrar was not checked.
			opt.RegistrarErr = safelog.Line(err.Error())
			logf("warn   : registrar unavailable: %s", opt.RegistrarErr)
		} else {
			regs = list
			c := domains.Compare(reg.Name(), entries, regs)
			cmp = &c
			opt.Registrar = reg.Name()
			orgOf = c.Covered
			logf("registrar: %d domain(s) in the %s account; %d inventory entr(ies) not there, "+
				"%d registration(s) not in the inventory", len(regs), reg.Name(),
				len(c.NotAtRegistrar), len(c.NotInInventory))
		}
	}

	selectors := domains.DefaultDKIMSelectors
	if s := strings.Fields(strings.ReplaceAll(os.Getenv("DOMAINS_DKIM_SELECTORS"), ",", " ")); len(s) > 0 {
		selectors = s
	}
	res := resolver
	if res == nil {
		res = net.DefaultResolver
	}
	web := webProber
	if web == nil {
		web = domains.NetWebProber(*timeout)
	}
	p := domains.Prober{Resolver: res, Web: web, Selectors: selectors,
		Concurrency: *concurrency, PerDomain: 4 * *timeout}
	results := p.Run(ctx, entries, orgOf)
	findings := domains.Evaluate(results, cmp, opt)

	prev, err := domains.LoadState(*statePath)
	if err != nil {
		// Fatal: carrying on would report "no changes" in a week that may
		// have had them, and overwrite the evidence.
		return die("%s", safelog.Line(err.Error()))
	}
	cur := domains.Snap(opt.Now, results, cmp, regs, prev)
	changes := domains.Diff(prev, cur, cmp != nil, opt.Registrar)

	rep := domains.Report{Now: opt.Now, Results: results, Findings: findings, Changes: changes,
		Registrar: opt.Registrar, RegistrarErr: opt.RegistrarErr, Problems: problems,
		FirstRun: prev == nil, Selectors: selectors}
	block := rep.Render()

	for _, w := range []struct{ path, body string }{
		{*out, block.HTML}, {*textOut, block.Text}, {*subjectOut, block.Subject + "\n"},
	} {
		if w.path == "" {
			continue
		}
		// 0600: a list of every domain we own and which ones are weak.
		if err := os.WriteFile(w.path, []byte(w.body), 0o600); err != nil {
			return die("writing %s: %s", safelog.Line(w.path), safelog.Line(err.Error()))
		}
		logf("wrote  : %s", safelog.Line(w.path))
	}
	if *out == "" && *textOut == "" {
		fmt.Print(block.Text)
	}

	// State LAST, after the report exists: a run that fails to render must
	// not advance the baseline and lose this week's changes.
	if *noStateWrite {
		logf("state  : not written (--no-state-write); next run still compares with %s",
			stateWhen(prev))
	} else {
		if err := os.MkdirAll(filepath.Dir(*statePath), 0o700); err != nil {
			return die("state dir: %s", safelog.Line(err.Error()))
		}
		if err := domains.SaveState(*statePath, cur); err != nil {
			return die("writing state: %s", safelog.Line(err.Error()))
		}
	}
	logf("subject: %s", safelog.Line(block.Subject))
	return exitOK
}

func stateWhen(s *domains.State) string {
	if s == nil {
		return "nothing (first run)"
	}
	return s.Taken.Format("2006-01-02")
}
