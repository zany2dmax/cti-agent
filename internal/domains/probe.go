package domains

import (
	"context"
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
	out := make([]Result, len(entries))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, e Entry) {
			defer wg.Done()
			defer func() { <-sem }()
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
	r.Web = append(r.Web, ProbeWeb(ctx, p.Resolver, p.Web, e.Name))
	// www for a registered domain. Without the registrar, a two-label name is
	// the best guess at "apex" this standard-library-only project can make.
	apex := org == e.Name || (org == "" && strings.Count(e.Name, ".") == 1)
	if apex && !strings.HasPrefix(e.Name, "www.") {
		r.Web = append(r.Web, ProbeWeb(ctx, p.Resolver, p.Web, "www."+e.Name))
	}
	r.Mail = ProbeMail(ctx, p.Resolver, e.Name, org, p.Selectors)
	return r
}
