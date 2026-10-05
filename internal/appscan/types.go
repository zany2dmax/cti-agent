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
// found twenty Urgent. The first application is not safer; the scanner covered
// a different surface.
//
// # THE DISTINCTION THIS TYPE EXISTS TO MAKE
//
// An earlier version of this package collapsed the whole question into one
// predicate, Blind(), meaning "not authenticated". That read every
// unauthenticated scan as a coverage gap, and the report named three
// applications as having one. All three are public sites with NO LOGIN AT ALL.
// There is nothing to authenticate as, so there is no missing credential, no
// gap, and nothing for anybody to go and fix. The report was raising a defect
// against the applications for being what they are.
//
// There are three states and they want different handling:
//
//	no credential configured   The scan covers the whole application, because
//	                           the whole application is public. A LABEL on the
//	                           scan - "unauthenticated scan" - so a reader
//	                           knows which surface the numbers describe.
//	configured and succeeded   Also a label - "authenticated scan".
//	configured and FAILED      A FAULT. Authentication was meant to happen here
//	                           and did not, so the scan covered less than it
//	                           was configured to cover while still looking
//	                           configured to anyone reading the setup. That is
//	                           the fleet operator's problem, not the App Dev
//	                           audience's - they cannot fix a scanner
//	                           credential - so it is alerted, not merely
//	                           printed.
//
// What survives from the old design is that the LABEL travels with every
// count. An unauthenticated scan's numbers are true about the public surface
// and silent about anything behind a login; a reader who does not know which
// kind of scan produced a zero cannot interpret the zero.
type Auth struct {
	// Record is the scanner's named credential set, empty when none.
	Record string
	// Status is the vendor's own wording - "Successful", "Failed",
	// "No Authentication specified".
	Status string
}

// Configured reports whether a credential set was attached to this scan.
//
// A property of the SETUP, not of the outcome. True says somebody intended
// this scan to log in; it says nothing about whether it managed to.
func (a Auth) Configured() bool { return a.Record != "" }

// Authenticated reports whether the scan actually got in.
//
// Requires BOTH a configured record and a successful status.
func (a Auth) Authenticated() bool {
	return a.Configured() && strings.EqualFold(a.Status, "successful")
}

// Failed reports a credential that was meant to work and did not.
//
// THE ONLY AUTH STATE THAT IS A FAULT. Compare with Authenticated(): a scan
// can be neither, which is the ordinary case for a site with no login.
//
// Two ways to be true, because either alone leaves a hole:
//
//   - the vendor says so. Requiring a named record as well would mean a
//     notification that states a failure but leaves the record field as
//     Qualys's literal "None" gets filed as an ordinary unauthenticated scan.
//     Not observed; cheap to cover, and the failure mode is silent.
//   - a record is configured and the status is not success. Covers a status
//     this code has never seen, including the empty string the parser leaves
//     when the vendor changes its template.
func (a Auth) Failed() bool {
	if strings.Contains(strings.ToLower(a.Status), "fail") {
		return true
	}
	return a.Configured() && !a.Authenticated()
}

// Label describes which surface this scan's numbers are about.
//
// The first two are plain descriptions, not verdicts: both are normal, and a
// reader needs to know which one produced a number before the number means
// anything. The third is a verdict, and it says so - a row of counts from a
// scan whose login broke must not sit under the same neutral tag as a public
// site that never had one.
func (a Auth) Label() string {
	switch {
	case a.Failed():
		return "authentication FAILED"
	case a.Authenticated():
		return "authenticated scan"
	}
	return "unauthenticated scan"
}

// ScanResult is one completed scan, normalised across vendors.
type ScanResult struct {
	Provider string // "qualys-was", "invicti", ...

	// App is the application as the operator named it, and ScanTitle is the
	// individual run. They differ: a title is typically "<app> Run #48".
	//
	// From email alone App is derived FROM the title, and on a real estate the
	// two rarely agree: "Example Run #47" for an application actually named
	// "Example Homepage". A provider with an API replaces it with the name the
	// scanner holds, which is the one its other endpoints accept.
	App       string
	ScanTitle string

	// AppID is the scanner's own stable identifier for the application, when
	// an API supplied it. Empty from email alone.
	//
	// It is the key for "one row per application" and for detail lookups.
	// Names are not: real ones carry trailing spaces and get renamed, and a
	// name-keyed lookup that misses returns an empty list - which reads
	// exactly like an application with nothing new.
	AppID string

	// NoNotification marks a scan the vendor's API reports but whose
	// completion email never reached the mailbox.
	//
	// Its counts are UNKNOWN, not zero - the counts come from the email - so
	// it must never be totalled or rendered as "nothing open". It is listed
	// so a missing notification is visible rather than a quietly thinner
	// report.
	NoNotification bool

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
	//
	// It ARRIVED IN MAIL, at a published address, so it is rendered as plain
	// text and never as an anchor, however well it verified.
	ReportURL   string
	LinkProblem string

	// PortalURL is a link this lane BUILT, from the vendor's API record of the
	// scan, into the vendor's own UI.
	//
	// The one URL the report may render as clickable, because nothing outside
	// supplied it: the scan ID came from an authenticated API call to the host
	// QUALYS_BASE_URL names, and the rest of the URL is a pattern in this
	// code. Even so the renderer re-checks it - https, and a host registered
	// with AllowPortalHosts - and falls back to plain text if it fails. A
	// constructed URL is still a string, and the check is the guarantee.
	PortalURL string

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

	// Potential marks a finding the scanner reports as possible but not
	// confirmed. Printed beside the title, because listing it with the
	// confirmed ones claims more than the scanner did.
	Potential bool
	// Ignored marks a finding somebody deliberately set aside in the
	// scanner's own console. Not shown as new work: that would re-raise a
	// decision a person already made, every week.
	Ignored bool
}

// Fault reports whether something is wrong with the SCAN, as distinct from
// something being wrong with the application.
//
// Two cases, and they share a consequence: this week's numbers for this
// application cannot be compared with last week's, because the measurement
// changed. An incomplete scan stopped early; a failed credential means it
// covered the public surface when it was set up to cover more.
//
// Both are the fleet operator's problem rather than the App Dev audience's -
// nobody writing application code can fix a scanner credential or a cancelled
// job - which is why this is the predicate cmd/cti-appscan alerts on.
//
// An unauthenticated scan with NO credential configured is not a fault. There
// is nothing missing: the scan covered what there was to cover.
func (s ScanResult) Fault() bool { return !s.Complete || s.Auth.Failed() }

// Attention reports whether a human should look at this scan now.
//
// New and Reopened findings, not the backlog: the backlog is the subject of a
// remediation programme, whereas something that appeared since the last scan
// is the thing a weekly report exists to surface.
//
// AN UNAUTHENTICATED SCAN IS NOT BY ITSELF ATTENTION. This used to return true
// for every scan that had not authenticated, which sorted three public sites
// with no login to the top of the report every week with nothing for anybody
// to do about them - and a permanent alarm is read as no alarm. A scan that was
// SUPPOSED to authenticate and could not is a different matter, and that is
// what Auth.Failed() picks out.
func (s ScanResult) Attention() bool {
	if s.Fault() {
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
	// Findings returns per-vulnerability detail for the scan's application.
	//
	// Takes the whole result, not a name, so an implementation can use AppID
	// when it is set. It used to take the name, and the name it was handed
	// came from the scan title - which matched the scanner's application name
	// in almost none of the real scans, so the lookup returned nothing and the
	// report said "detail not available" for nearly every application.
	Findings(ctx context.Context, s ScanResult, since time.Time) ([]Finding, error)
}
