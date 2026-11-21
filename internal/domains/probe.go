package domains

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Result is everything observed about one inventory entry.
type Result struct {
	Entry Entry
	// Org is the registration covering the entry, "" when the registrar was
	// not consulted or does not hold it.
	Org string
	// NS is the delegation DNS reports for the entry's own name.
	NS   Lookup
	Web  []Web // the name, then www.<name> for an apex entry
	Mail Mail
	// Route is how the domain's mail flows relative to the Proofpoint on
	// Demand gateway; RouteChecked is false when that check is off (no
	// domain on PoD). Filled by AssignRoutes after probing.
	Route        Route
	RouteChecked bool
	// Fault is set when probing this entry crashed (a bug, or a page built to
	// trigger one). The entry was not checked, and Evaluate says so; the other
	// entries are unaffected.
	Fault string
}

// Live reports whether any probed host answered.
func (r Result) Live() bool {
	for _, w := range r.Web {
		if w.Live() {
			return true
		}
	}
	return false
}

// Prober runs the per-domain checks.
type Prober struct {
	Resolver    Resolver
	Web         WebProber
	Selectors   []string
	Concurrency int
	// PerDomain bounds one domain's whole probe, so one black-holed name
	// cannot hold the run.
	PerDomain time.Duration
	// SMTP, when set, greets the first answering MX of every domain that has
	// one (the original checker's -smtp). nil: not checked, and the report
	// says so.
	SMTP SMTPProber
	// AllowPrivate lets the web probe fetch a host that resolves to a private
	// or reserved address (DOMAINS_ALLOW_PRIVATE=1). Off by default: see probeWeb.
	AllowPrivate bool

	smtp *smtpCache
}

// Run probes every entry. Order is preserved.
//
// orgOf maps an entry name to its registration, for the DMARC fallback and
// the www probe; nil when the registrar was not consulted.
func (p Prober) Run(ctx context.Context, entries []Entry, orgOf map[string]Registration) []Result {
	n := p.Concurrency
	if n <= 0 {
		n = 8
	}
	per := p.PerDomain
	if per <= 0 {
		per = 60 * time.Second
	}
	if p.SMTP != nil {
		p.smtp = newSMTPCache(p.SMTP)
	}
	out := make([]Result, len(entries))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, e Entry) {
			defer wg.Done()
			defer func() { <-sem }()
			// One domain's crash must not take the run down with it: the
			// weekly would send nothing at all.
			defer func() {
				if rec := recover(); rec != nil {
					out[i] = faulted(e, orgOf[e.Name].Domain, fmt.Sprintf("probing crashed: %v", rec))
				}
			}()
			dctx, cancel := context.WithTimeout(ctx, per)
			defer cancel()
			out[i] = p.one(dctx, e, orgOf[e.Name].Domain)
		}(i, e)
	}
	wg.Wait()
	return out
}

func (p Prober) one(ctx context.Context, e Entry, org string) Result {
	r := Result{Entry: e, Org: org}
	r.NS = lookupNS(ctx, p.Resolver, e.Name)
	r.Web = append(r.Web, probeWeb(ctx, p.Resolver, p.Web, e.Name, p.AllowPrivate))
	// www for a registered domain. Without the registrar, a two-label name is
	// the best guess at "apex" this standard-library-only project can make.
	apex := org == e.Name || (org == "" && strings.Count(e.Name, ".") == 1)
	if apex && !strings.HasPrefix(e.Name, "www.") {
		r.Web = append(r.Web, probeWeb(ctx, p.Resolver, p.Web, "www."+e.Name, p.AllowPrivate))
	}
	r.Mail = ProbeMail(ctx, p.Resolver, e.Name, org, p.Selectors)
	if p.smtp != nil && r.Mail.MX.Present() {
		r.Mail.SMTP = p.smtp.first(ctx, r.Mail.MX.Values, r.Mail.MXUnresolved)
	}
	return r
}

// faulted is the Result for an entry whose probe crashed. Every lookup in it is
// a FAILED lookup (Err set), not an empty answer: the state file, the route
// check and the change report all treat "unknown" as "carry last week's value
// forward", and an empty answer as "the records were removed".
func faulted(e Entry, org, why string) Result {
	failed := Lookup{Err: why}
	return Result{Entry: e, Org: org, Fault: why, NS: failed,
		Mail: Mail{MX: failed, SPF: failed, DMARC: failed}}
}
