package appscan

import (
	"context"
	"time"
)

// Scanner is a scanner's API, as the lane sees it. Only a name is required.
// Everything the API can do is an optional capability found by type assertion,
// the way DetailFetcher and RemedyFetcher already are: a scanner that can list
// its scans but not its applications still works, with the lane doing less.
//
// cmd/cti-appscan names no vendor except in wiring.go. A new scanner is a
// package that implements the capabilities it has, plus one line there.
type Scanner interface {
	// Name is the provider key stored on results; it equals the Name of the
	// Provider that parses the same vendor's notifications.
	Name() string
}

// Reconciler joins notification results to the scanner's own scan list. It
// adds the scans whose mail never arrived, and takes the application's real
// identity from the scanner rather than from a scan title.
//
// An error means the list was unavailable; the caller keeps the results it
// has, since the counts are in the notifications.
type Reconciler interface {
	Reconcile(ctx context.Context, results []ScanResult, since time.Time) ([]ScanResult, Reconciliation, error)
}

// Reconciliation says what joining the mailbox to the scan list found.
//
// Every number here is something that would otherwise have been silent: a
// notification the scanner has no record of, or a scan it ran whose email
// never arrived.
type Reconciliation struct {
	// Listed is how many scans the scanner returned for the window.
	Listed  int
	Matched int
	// Unmatched are scan references from notifications that the scan list did
	// not contain. Usually a scan launched before the window; worth a
	// warning, never a reason to drop the notification's counts.
	Unmatched []string
	// Skipped counts scans deliberately left out: discovery scans, which test
	// nothing, and scans still running.
	Skipped int
	// IDMismatch are scan references whose notification named a different
	// application id from the one the scan list gives. The scanner's id is the
	// one kept; a mismatch means a forged notice or a template change, and
	// either is worth a warning.
	IDMismatch []string
	// NoPortal is set when the scanner's address maps to no known web UI, so
	// the report's links stay plain text from the notifications.
	NoPortal bool
}

// AppLister lists every application the scanner defines, not only the ones
// scanned this week: an application nobody owns is a ticket nobody is
// assigned.
type AppLister interface {
	Apps(ctx context.Context) ([]App, error)
}

// OpenFetcher returns every finding the scanner still holds open for the
// scan's application, for the tickets.
type OpenFetcher interface {
	OpenFindings(ctx context.Context, s ScanResult) ([]Finding, error)
}

// ReferenceChecker is implemented by a provider that can tell a real scan
// reference from a mangled one. Without it any non-empty reference counts.
type ReferenceChecker interface {
	WellFormedReference(ref string) bool
}

// PortalHoster is implemented by a provider whose report links this lane
// builds. It names the web hosts those links may point at; every other host
// stays plain text.
type PortalHoster interface {
	PortalHosts() []string
}

// WellFormed reports whether ref is a usable scan reference for p.
func WellFormed(p Provider, ref string) bool {
	if c, ok := p.(ReferenceChecker); ok {
		return c.WellFormedReference(ref)
	}
	return ref != ""
}
