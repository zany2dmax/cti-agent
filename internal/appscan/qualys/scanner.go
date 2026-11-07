package qualys

import (
	"context"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// The capabilities the AppSec lane looks for on a scanner. Asserted here so a
// change to either side fails the build rather than quietly disabling a
// feature at run time.
var (
	_ appscan.Scanner          = (*API)(nil)
	_ appscan.Reconciler       = (*API)(nil)
	_ appscan.AppLister        = (*API)(nil)
	_ appscan.OpenFetcher      = (*API)(nil)
	_ appscan.DetailFetcher    = (*API)(nil)
	_ appscan.RemedyFetcher    = (*API)(nil)
	_ appscan.ReferenceChecker = Provider{}
	_ appscan.PortalHoster     = Provider{}
)

// Reconcile implements appscan.Reconciler: the WAS scan list, joined to the
// notifications.
func (a *API) Reconcile(ctx context.Context, results []appscan.ScanResult, since time.Time) ([]appscan.ScanResult, appscan.Reconciliation, error) {
	list, err := a.Scans(ctx, since.Add(-ScanMargin))
	if err != nil {
		return results, appscan.Reconciliation{}, err
	}
	portal := PortalOrigin(a.baseURL)
	out, rec := Reconcile(results, list, since, portal)
	rec.Listed = len(list)
	rec.NoPortal = portal == ""
	return out, rec, nil
}

// Apps implements appscan.AppLister.
func (a *API) Apps(ctx context.Context) ([]appscan.App, error) {
	in, err := a.WebApps(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]appscan.App, 0, len(in))
	for _, w := range in {
		out = append(out, appscan.App{ID: w.ID, Name: w.Name, URL: w.URL})
	}
	return out, nil
}

// WellFormedReference implements appscan.ReferenceChecker.
func (Provider) WellFormedReference(ref string) bool { return WellFormedReference(ref) }

// PortalHosts implements appscan.PortalHoster.
func (Provider) PortalHosts() []string { return PortalHosts }
