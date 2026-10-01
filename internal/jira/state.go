package jira

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PropertyKey is where exposure state lives: on the issue itself.
//
// NOT in a file on the fleet box. Same reasoning as IdempotencyLabel - a
// ticket can be closed, cloned, moved between projects or bulk-edited in the
// UI, and any local record of what the fleet believes about it goes stale the
// moment somebody does. State attached to the issue travels with the issue.
//
// It also means a rebuilt fleet box does not re-announce every host it has
// ever seen as newly discovered, which is the failure that would make the
// comments untrustworthy on exactly the day they mattered.
const PropertyKey = "cti-agent-exposure"

// MaxPropertyHosts bounds the STORED host list - the diff bookkeeping only.
//
// IT DOES NOT BOUND THE CSV. Three limits exist in this package and they do
// three different jobs:
//
//	CSV attachment      no limit   the deliverable: every hostname, always
//	MaxListedInComment  20         how many a comment names in prose
//	MaxPropertyHosts    800        how many are remembered for the next diff
//
// A ticket with no hostnames to work on is useless, so the attachment is
// never truncated. Past this limit the fleet loses only the ability to say
// WHICH hosts are new - the CSV on the ticket still lists all of them.

// Jira caps an issue property at 32KB. A 441-host list is roughly 11KB, so
// the real estate is there - but "roughly" is not a guarantee, and a property
// write that 400s partway through a run would leave the ticket commented and
// the state unwritten, which double-reports every host next time. Past this
// many, the list is dropped and only the hash and count are kept: the fleet
// then reports that the count changed without being able to name which hosts,
// and says so rather than implying it knows.
const MaxPropertyHosts = 800

// ExposureState is what the fleet believed about a CVE when it last looked.
type ExposureState struct {
	CVE       string    `json:"cve"`
	Hosts     []string  `json:"hosts,omitempty"`
	HostsHash string    `json:"hosts_hash"`
	HostCount int       `json:"host_count"`
	HostsKept bool      `json:"hosts_kept"`
	QIDs      []string  `json:"qids"`
	UpdatedAt time.Time `json:"updated_at"`
	TicketKey string    `json:"ticket_key"`

	// ClosedButDetectedAt records that the fleet has already said a closed
	// ticket still has live detections. Without it, every run says it again,
	// and a ticket somebody deliberately closed becomes a daily argument.
	ClosedButDetectedAt time.Time `json:"closed_but_detected_at,omitempty"`
}

// HostsHashOf fingerprints a host set, order-independently.
//
// Sorted before hashing because the scanner does not promise an order, and a
// hash that changes when the same hosts come back in a different sequence
// would report drift on every single run.
func HostsHashOf(hosts []string) string {
	norm := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			norm = append(norm, h)
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// StateFrom builds the state to store for a finding.
func StateFrom(f Finding, ticketKey string, now time.Time) ExposureState {
	s := ExposureState{
		CVE:       f.CVE,
		HostsHash: HostsHashOf(f.Hosts),
		// Count() not len(Hosts): when the scanner truncates, the number of
		// NAMES it returned moves around independently of the estate, and a
		// drift report built on that reads a short scan as remediation.
		HostCount: f.Count(),
		QIDs:      sortedCopy(f.QIDs),
		UpdatedAt: now,
		TicketKey: ticketKey,
	}
	if len(f.Hosts) > 0 && len(f.Hosts) <= MaxPropertyHosts {
		s.Hosts = sortedCopy(f.Hosts)
		s.HostsKept = true
	}
	return s
}

// Drift is what changed between two looks at the same CVE.
type Drift struct {
	NewHosts  []string
	GoneHosts []string
	NewQIDs   []string
	GoneQIDs  []string

	CountBefore int
	CountAfter  int

	// HostsUnknown means the previous run could not store its host list, so
	// only the totals can be compared. The comment must then say the count
	// moved WITHOUT naming hosts, rather than listing the current set as if
	// it were all new.
	HostsUnknown bool

	// Resolved means the scanner no longer detects this anywhere. The one
	// piece of good news this lane can deliver, and the signal IT needs to
	// close the ticket.
	Resolved bool

	// FirstLook means there was no stored state - an older ticket, or one
	// filed before state was recorded. Not drift, and must not be reported
	// as every host appearing at once.
	FirstLook bool
}

// DiffExposure compares stored state against what the scanner reports now.
func DiffExposure(prev *ExposureState, f Finding, _ time.Time) Drift {
	d := Drift{CountAfter: f.Count()}

	if prev == nil {
		d.FirstLook = true
		d.Resolved = f.Count() == 0
		return d
	}
	d.CountBefore = prev.HostCount
	d.Resolved = f.Count() == 0 && prev.HostCount > 0

	d.NewQIDs, d.GoneQIDs = diffSets(prev.QIDs, f.QIDs)

	if !prev.HostsKept {
		d.HostsUnknown = true
		return d
	}
	d.NewHosts, d.GoneHosts = diffSets(prev.Hosts, f.Hosts)
	return d
}

// diffSets returns what is in b but not a, and in a but not b.
// Case-insensitive: the scanner is not consistent about hostname case, and
// HOST-A reappearing as host-a is not a new host.
func diffSets(a, b []string) (added, removed []string) {
	inA, inB := map[string]string{}, map[string]string{}
	for _, v := range a {
		if k := strings.ToLower(strings.TrimSpace(v)); k != "" {
			inA[k] = v
		}
	}
	for _, v := range b {
		if k := strings.ToLower(strings.TrimSpace(v)); k != "" {
			inB[k] = v
		}
	}
	for k, v := range inB {
		if _, ok := inA[k]; !ok {
			added = append(added, v)
		}
	}
	for k, v := range inA {
		if _, ok := inB[k]; !ok {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// Material reports whether this drift is worth saying out loud.
//
// THIS IS THE WHOLE ANTI-NOISE DECISION, so it is deliberately narrow:
//
//   - growth is material. More hosts, or a new QID, means the exposure got
//     worse and somebody should know today rather than at the next review.
//   - reaching zero is material. It is the only good news this lane produces
//     and it is what tells IT they are finished.
//   - shrinking is NOT material on its own. A set that goes 441 -> 438 -> 441
//     as machines reboot, agents drop off and scans partially complete would
//     otherwise generate a comment most mornings. A ticket that is commented
//     on daily is a ticket whose comments nobody reads, and this lane exists
//     precisely because the operator said not to storm IT.
//   - first look is NOT material. No stored state means an older ticket, not
//     a discovery, and announcing every host at once would be a lie told
//     loudly.
//
// A shrinking count is still recorded in the stored state, so it is visible
// the moment anything else prompts a comment. Quiet is not the same as lost.
func (d Drift) Material() bool {
	if d.FirstLook {
		return false
	}
	if d.Resolved {
		return true
	}
	if len(d.NewQIDs) > 0 {
		return true
	}
	if d.HostsUnknown {
		// Without a stored list, growth can only be seen in the total.
		return d.CountAfter > d.CountBefore
	}
	return len(d.NewHosts) > 0
}

// MaxListedInComment bounds how many hostnames a comment names.
//
// A comment that lists 400 hosts is one nobody reads to the end, and the full
// set is attached as a CSV on the same update. Naming a few is enough to show
// what kind of host appeared.
const MaxListedInComment = 20

// DriftComment renders the update. Jira wiki markup, matching Description.
//
// Written to be read in a notification email, which is where most of these
// will actually be seen: the first line says what changed and by how much,
// because that is all a reader gets before deciding whether to open it.
func DriftComment(d Drift, f Finding, csvName string, now time.Time) string {
	var b strings.Builder

	switch {
	case d.Resolved:
		b.WriteString("*No detections remain.* The scanner no longer reports ")
		b.WriteString(f.CVE + " on any host ")
		_, _ = fmt.Fprintf(&b, "(was %d). This ticket can be closed.\n\n", d.CountBefore)
		b.WriteString("Reported by the CTI agent on " + now.Format("2006-01-02") + ".\n")
		return b.String()

	case d.HostsUnknown:
		_, _ = fmt.Fprintf(&b,
			"*Exposure grew: %d -> %d hosts* (+%d).\n\n",
			d.CountBefore, d.CountAfter, d.CountAfter-d.CountBefore)
		b.WriteString("The previous host list was too large to store on this ticket, ")
		b.WriteString("so the individual new hosts cannot be named - only the totals ")
		b.WriteString("are comparable. The current full list is attached.\n\n")

	default:
		_, _ = fmt.Fprintf(&b, "*Exposure changed: %d -> %d hosts.*\n\n",
			d.CountBefore, d.CountAfter)
	}

	if len(d.NewHosts) > 0 {
		_, _ = fmt.Fprintf(&b, "h4. %d newly affected host(s)\n", len(d.NewHosts))
		writeList(&b, d.NewHosts)
	}
	if len(d.NewQIDs) > 0 {
		_, _ = fmt.Fprintf(&b, "h4. %d new QID(s): %s\n\n",
			len(d.NewQIDs), strings.Join(d.NewQIDs, ", "))
	}

	// Remediated hosts are reported when something else already earned a
	// comment, but never trigger one. Progress is worth seeing; it is not
	// worth an interruption.
	if len(d.GoneHosts) > 0 {
		_, _ = fmt.Fprintf(&b, "h4. %d host(s) no longer detected\n", len(d.GoneHosts))
		writeList(&b, d.GoneHosts)
	}
	if len(d.GoneQIDs) > 0 {
		_, _ = fmt.Fprintf(&b, "h4. %d QID(s) no longer detected: %s\n\n",
			len(d.GoneQIDs), strings.Join(d.GoneQIDs, ", "))
	}

	if csvName != "" {
		_, _ = fmt.Fprintf(&b, "The current full host list is attached as [^%s].\n", csvName)
	}
	return b.String()
}

func writeList(b *strings.Builder, items []string) {
	shown := items
	if len(shown) > MaxListedInComment {
		shown = shown[:MaxListedInComment]
	}
	for _, h := range shown {
		b.WriteString("* " + h + "\n")
	}
	if len(items) > len(shown) {
		_, _ = fmt.Fprintf(b, "* ...and %d more, in the attached CSV\n", len(items)-len(shown))
	}
	b.WriteString("\n")
}

// ClosedButDetectedComment is said ONCE on a closed ticket that the scanner
// still reports detections for.
//
// The fleet does not reopen the ticket. Somebody closed it deliberately -
// they may have an exception, a compensating control, or a replacement
// ticket - and software that reverses a human decision every night is
// software that gets switched off. Saying it once is the whole intervention.
func ClosedButDetectedComment(f Finding, now time.Time) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b,
		"*This ticket is closed, but %s is still detected on %d host(s).*\n\n",
		f.CVE, f.Count())
	b.WriteString("The CTI agent has not reopened it and will not comment again - ")
	b.WriteString("closing it may well have been right. If it was closed in error, ")
	b.WriteString("reopen it; if the exposure is accepted, no action is needed.\n\n")
	b.WriteString("Noted on " + now.Format("2006-01-02") + ".\n")
	return b.String()
}
