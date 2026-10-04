// Package appscan is the swappable boundary for dynamic application security
// testing — DAST — the way internal/vulnlookup is the boundary for host
// vulnerability management.
//
// # WHY THE SHAPE DIFFERS FROM vulnlookup
//
// vulnlookup.LookupProvider is QUERY-shaped: you hand it a CVE and ask whether
// the estate has it. DAST is PUSH-shaped: a scanner finishes and tells you. So
// the primitive here is "recognise and parse a vendor's completion
// notification", not "look something up".
//
// That split is also what keeps a provider cheap to add. Qualys WAS, Invicti
// and Wiz all mail a completion summary, and parsing one needs no credentials
// at all — which means a new provider can be useful before anybody has
// negotiated API access for it. Providers that DO have an API additionally
// implement DetailFetcher.
//
// # THE TWO COUNT SYSTEMS, WHICH ARE NOT THE SAME NUMBER
//
// A Qualys WAS notification carries both, and they differ by a factor of
// twenty on a real application:
//
//   - ScanCounts     what THIS scan found.            One app: 58.
//   - AppCounts      the application's LIFECYCLE state. Same app: 1270 total,
//     of which 247 "Urgent" are Fixed and 23 are Active.
//
// Reporting the lifecycle total as if it were current exposure would have
// announced 270 Urgent findings on an application that has 23. Reporting the
// per-scan number as if it were the open backlog understates it differently.
// They are kept in separate types so a caller has to say which it means, and
// Active is the field that anything actionable should read.
package appscan

import (
	"context"
	"strings"
	"time"
)

// Severity is the scanner's own severity, 1 (lowest) to 5 (highest).
//
// DELIBERATELY NOT THE FLEET'S Sev1–Sev5. Those mean "confirmed present in the
// estate AND known to be exploited", which is a claim about the world. A
// Qualys WAS "Severity 5 Urgent" is a claim about one HTTP response. Rendering
// them in the same namespace would let a web finding borrow the urgency of a
// KEV entry, so anything that prints these must label the scale.
type Severity int

// Counts is one severity band's worth of numbers, as five buckets.
type Counts struct {
	Urgent  int // severity 5
	Crit    int // severity 4
	Serious int // severity 3
	Medium  int // severity 2
	Minimal int // severity 1
}

// Total sums the bands. Named rather than left to callers because the
// notification states its own total, and a mismatch between that and the sum
// means the parse missed a line.
func (c Counts) Total() int {
	return c.Urgent + c.Crit + c.Serious + c.Medium + c.Minimal
}

// Worst returns the highest severity with a non-zero count, or 0.
func (c Counts) Worst() Severity {
	switch {
	case c.Urgent > 0:
		return 5
	case c.Crit > 0:
		return 4
	case c.Serious > 0:
		return 3
	case c.Medium > 0:
		return 2
	case c.Minimal > 0:
		return 1
	}
	return 0
}

// Lifecycle is where an application's findings stand after a scan.
//
// Active is the only field that describes current exposure. Total includes
// everything the application has ever had, and Fixed is usually most of it.
type Lifecycle struct {
	Total    Counts
	New      Counts
	Reopened Counts
	Active   Counts
	Fixed    Counts
	Ignored  Counts
}

// Auth is what the scanner was able to authenticate as.
//
// This is the most important field in the whole package, and it is not a
// vulnerability count.
//
// Observed on two scans run the same night by the same scanner: an
// unauthenticated scan crawled 252 links and reported zero Urgent and zero
// Critical. An authenticated scan of a different application crawled 67 and
// found twenty Urgent. The first application is not safer; the scanner never
// got past the front door.
//
// A clean result from an unauthenticated scan is therefore not evidence of
// anything, and reporting its zeroes without saying so is the exact failure
// this codebase keeps having to fix: a number that looks like good news and
// means nothing.
type Auth struct {
	// Record is the scanner's named credential set, empty when none.
	Record string
	// Status is the vendor's own wording - "Successful", "Failed",
	// "No Authentication specified".
	Status string
}

// Authenticated reports whether the scan actually got in.
//
// Requires BOTH a configured record and a successful status. A configured
// record that failed to authenticate produces the same blind scan as no record
// at all, while looking configured to anyone reading the setup.
func (a Auth) Authenticated() bool {
	return a.Record != "" && strings.EqualFold(a.Status, "successful")
}

// Blind reports whether this scan's results describe only the public surface.
func (a Auth) Blind() bool { return !a.Authenticated() }

// ScanResult is one completed scan, normalised across vendors.
type ScanResult struct {
	Provider string // "qualys-was", "invicti", ...

	// App is the application as the operator named it, and ScanTitle is the
	// individual run. They differ: a title is typically "<app> Run #48".
	App       string
	ScanTitle string
	// Reference is the vendor's scan identifier, used to deduplicate when the
	// same notification is seen twice.
	Reference string
	// Target is what was scanned, as the vendor describes it.
	Target string

	Started  time.Time
	Finished time.Time

	Auth Auth

	// Status is the vendor's completion status, verbatim.
	Status string
	// Complete reports whether the scan ran to completion. Counts from a scan
	// that was cancelled or hit a time limit describe a partial crawl, and
	// presenting them as a result is reporting a measurement that was never
	// taken.
	Complete bool

	LinksCrawled int

	// ScanCounts is what this run found. ScanDelta is the vendor's own
	// comparison against the previous scan, which saves keeping state.
	ScanCounts Counts
	ScanDelta  Counts

	// AppState is the application-level lifecycle after this scan.
	// Read Active for current exposure; Total is mostly history.
	AppState Lifecycle

	// ReportURL is a link to the vendor's report, verified to belong to that
	// vendor. Empty when the link could not be verified - see LinkProblem.
	ReportURL   string
	LinkProblem string

	// Findings is per-vulnerability detail, present only when a DetailFetcher
	// filled it in. Nil means "not fetched", NOT "none found".
	Findings []Finding
}

// Finding is one vulnerability on one URL.
type Finding struct {
	ID        string // vendor's QID or equivalent
	Title     string
	Severity  Severity
	URL       string
	Param     string
	Status    string // NEW, ACTIVE, REOPENED, FIXED
	FirstSeen time.Time
	LastSeen  time.Time
}

// Attention reports whether a human should look at this scan now.
//
// New and Reopened findings, not the backlog: the backlog is the subject of a
// remediation programme, whereas something that appeared since the last scan
// is the thing a weekly report exists to surface. A blind scan always warrants
// attention regardless of its counts, because its counts are not evidence.
func (s ScanResult) Attention() bool {
	if !s.Complete || s.Auth.Blind() {
		return true
	}
	n, r := s.AppState.New, s.AppState.Reopened
	return n.Urgent+n.Crit+n.Serious+r.Urgent+r.Crit+r.Serious > 0
}

// Provider parses one vendor's completion notifications.
//
// No credentials are required to implement this, which is the point: a new
// scanner becomes useful the day its email arrives, not the day somebody
// negotiates API access.
type Provider interface {
	// Name is the stable provider key stored on results.
	Name() string
	// Recognises reports whether this message is one of ours, from the sender
	// and subject alone - cheap enough to run over every message in a run.
	Recognises(sender, subject string) bool
	// Parse turns the message body into a result, plus any problems worth
	// reporting. Problems are not errors: a notification that parsed most of
	// the way is still worth reporting, and a vendor template change should
	// announce itself rather than show up as a quietly thinner report.
	Parse(body string) (ScanResult, []string)
}

// DetailFetcher is implemented only by providers with an API.
//
// Separate from Provider so that the email-only path needs no credentials and
// cannot be broken by an API outage. A caller that cannot fetch detail still
// has the counts.
type DetailFetcher interface {
	// Findings returns per-vulnerability detail for one application.
	Findings(ctx context.Context, app string, since time.Time) ([]Finding, error)
}

