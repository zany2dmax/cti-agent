package appscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ONE TICKET PER APPLICATION
//
// The weekly email tells App Dev what changed; a ticket is what somebody is
// assigned and works. One open ticket per application, assigned to the owner
// in app-owners.txt, carrying every active, confirmed finding of Serious
// severity or above - and every POTENTIAL one of Critical or Urgent, in a
// section of its own (see PotentialMinSeverity) - with WHERE it is, WHAT the scanner saw, the RISK, and HOW
// TO FIX IT - the knowledge base's own solution text. Each week the ticket is
// commented only when that set of findings changed, and told once when
// nothing is left.
//
// cti-appscan builds this file; cti-jira --appscan-tickets files it. Same
// split as the domains lane: the component that talks to the scanner is not
// the component that writes to Jira.

// TicketMinSeverity is the lowest severity that goes on a ticket: Serious.
// Medium and Minimal are counted on the ticket, not listed.
const TicketMinSeverity = 3

// PotentialMinSeverity is the lowest severity at which a POTENTIAL finding -
// one the scanner reports as possible but could not confirm - goes on the
// ticket: Critical. Listed in its own section, marked as unconfirmed on every
// line, so a developer verifies it rather than either fixing a false positive
// blind or being told "the scanner didn't confirm it" means it isn't there.
// At Critical and Urgent an unconfirmed finding is still worth a person's
// look; below that, potentials are left out as before.
const PotentialMinSeverity = 4

// maxInstances is how many URL/parameter instances one finding lists before
// "and N more". A finding on 400 pages of the same template is one fix.
const maxInstances = 25

// TicketsFile is cti-appscan --tickets-out.
type TicketsFile struct {
	Generated time.Time   `json:"generated"`
	Tickets   []AppTicket `json:"tickets"`
	// Unowned are web apps defined in the scanner with no owner in
	// app-owners.txt, scanned this week or not.
	Unowned []string `json:"unowned,omitempty"`
	// NotScanned are live websites (from the domains lane) that no web app
	// in the scanner points at: a coverage gap. SitesAsOf is when the
	// domains lane observed them.
	NotScanned []NotScanned `json:"notScanned,omitempty"`
	// ViaStandIn are live websites covered only by a stand-in web app
	// (covers=): listed, because "covered via staging" is not "scanned".
	ViaStandIn []ViaStandIn `json:"viaStandIn,omitempty"`
	SitesAsOf  time.Time    `json:"sitesAsOf,omitempty"`
	// ScannerApps are the ids of EVERY web app the scanner defines, set only
	// when the whole list was fetched. cti-jira closes the ticket of an
	// application whose id is missing from it, so an absent list (the fetch
	// failed, or was skipped) must stay absent: "unknown" is never "gone".
	ScannerApps []string `json:"scannerApps,omitempty"`
}

// ViaStandIn is one production site and the web app that stands in for it.
type ViaStandIn struct {
	Domain  string `json:"domain"`
	AppID   string `json:"appId"`
	AppName string `json:"appName"`
	AppHost string `json:"appHost"`
}

// NotScanned is one live website with no web application scan.
type NotScanned struct {
	Domain string `json:"domain"`
	URL    string `json:"url,omitempty"`
	Owner  string `json:"owner,omitempty"` // from a site: line in app-owners.txt
}

// AppTicket is one application's ticket input.
type AppTicket struct {
	// Key identifies the application across runs: "id:<scanner id>" when the
	// scan list supplied one, else "name:<application name>".
	Key   string `json:"key"`
	App   string `json:"app"`
	AppID string `json:"appId,omitempty"`
	// Target is the scanned URL.
	Target    string    `json:"target,omitempty"`
	PortalURL string    `json:"portalUrl,omitempty"`
	Scanned   time.Time `json:"scanned"`
	ScanLabel string    `json:"scanLabel"` // authenticated / unauthenticated scan

	Owner       string `json:"owner,omitempty"` // email, from app-owners.txt
	Component   string `json:"component,omitempty"`
	OwnerListed bool   `json:"ownerListed"`
	// Covers are production sites this web app stands in for (covers= in
	// app-owners.txt): the ticket says the fix goes into the code and then
	// gets deployed, because production itself is not what was scanned.
	Covers []string `json:"covers,omitempty"`
	// Watchers are extra emails to add as Jira watchers (watchers= in
	// app-owners.txt).
	Watchers []string `json:"watchers,omitempty"`

	// Skip, when set, is why Jira must not be touched for this application
	// this week: the scan did not complete or failed to authenticate, or the
	// per-finding detail could not be fetched. "Nothing found" from a scan
	// that did not cover the application would tell its ticket everything
	// was fixed.
	Skip string `json:"skip,omitempty"`

	Findings []TicketFinding `json:"findings"`
	// Lower is the count of active Medium and Minimal findings, not listed.
	Lower int `json:"lower"`
	// Hash fingerprints the listed findings (QID + URL + parameter), so a
	// week with the same open findings posts nothing.
	Hash string `json:"hash"`
}

// TicketFinding is one QID on one application, with every place it was seen.
type TicketFinding struct {
	ID        string     `json:"id"` // QID
	Title     string     `json:"title"`
	Severity  Severity   `json:"severity"`
	Status    string     `json:"status"` // worst of NEW / REOPENED / ACTIVE across instances
	FirstSeen time.Time  `json:"firstSeen"`
	Instances []Instance `json:"instances"`
	More      int        `json:"more,omitempty"` // instances beyond the listed ones
	Remedy    *Remedy    `json:"remedy,omitempty"`
	// Potential: the scanner reports it as possible, not confirmed. Only at
	// PotentialMinSeverity and above, and always rendered as such.
	Potential bool `json:"potential,omitempty"`
}

// Instance is one place a finding was seen.
type Instance struct {
	URL   string `json:"url"`
	Param string `json:"param,omitempty"`
	// Evidence is not part of the fingerprint: a different response body
	// for the same finding in the same place is not a change worth a comment.
	Evidence *Evidence `json:"evidence,omitempty"`
}

// InstanceKeys are the fingerprints of a ticket's listed findings, for
// saying what is new and what is gone since the last comment.
func (t AppTicket) InstanceKeys() []string {
	var out []string
	for _, f := range t.Findings {
		for _, in := range f.Instances {
			out = append(out, f.InstanceKey(in))
		}
	}
	sort.Strings(out)
	return out
}

// InstanceKey fingerprints one place. A potential finding's key ends "|p",
// so one that becomes confirmed (or the reverse) reads as changed and the
// ticket is told, rather than keeping its old label. The QID stays first:
// the ticket state keeps it in clear.
func (f TicketFinding) InstanceKey(in Instance) string {
	k := f.ID + "|" + in.URL + "|" + in.Param
	if f.Potential {
		k += "|p"
	}
	return k
}

// SeverityName is the scanner's word for a severity.
func SeverityName(s Severity) string {
	switch s {
	case 5:
		return "Urgent"
	case 4:
		return "Critical"
	case 3:
		return "Serious"
	case 2:
		return "Medium"
	case 1:
		return "Minimal"
	}
	return "Unknown"
}

// Worst is the highest listed severity, 0 when none.
func (t AppTicket) Worst() Severity {
	var w Severity
	for _, f := range t.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// AppKey is how an application is identified across runs.
func AppKey(s ScanResult) string {
	if id := strings.TrimSpace(s.AppID); id != "" {
		return "id:" + id
	}
	return "name:" + strings.ToLower(strings.Join(strings.Fields(s.App), " "))
}

var labelSafeRE = regexp.MustCompile(`[^a-z0-9]+`)

// AppLabel is the Jira label that finds this application's ticket. Labels
// cannot contain spaces, so a name is reduced to [a-z0-9-] - and gets a short
// hash so two names that reduce alike do not share a ticket.
func AppLabel(key string) string {
	if id := strings.ToLower(strings.TrimPrefix(key, "id:")); strings.HasPrefix(key, "id:") {
		if clean := labelSafeRE.ReplaceAllString(id, ""); clean == id && clean != "" {
			return "cti-appscan-" + clean // a plain scanner id: readable, and unique
		}
	}
	slug := strings.Trim(labelSafeRE.ReplaceAllString(strings.TrimPrefix(key, "name:"), "-"), "-")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	sum := sha256.Sum256([]byte(key))
	return "cti-appscan-" + slug + "-" + hex.EncodeToString(sum[:])[:6]
}

// Split returns the ticket's confirmed and potential findings, in order.
func Split(fs []TicketFinding) (confirmed, potential []TicketFinding) {
	for _, f := range fs {
		if f.Potential {
			potential = append(potential, f)
		} else {
			confirmed = append(confirmed, f)
		}
	}
	return confirmed, potential
}

func ticketable(f Finding) bool {
	if f.Ignored {
		return false
	}
	if f.Potential && f.Severity < PotentialMinSeverity {
		return false
	}
	if f.Severity < TicketMinSeverity {
		return false
	}
	switch f.Status {
	case "NEW", "ACTIVE", "REOPENED":
		return true
	}
	return false
}

func lowerActive(f Finding) bool {
	if f.Severity >= TicketMinSeverity || f.Severity <= 0 || f.Potential || f.Ignored {
		return false
	}
	switch f.Status {
	case "NEW", "ACTIVE", "REOPENED":
		return true
	}
	return false
}

func statusRank(s string) int {
	switch s {
	case "REOPENED":
		return 3
	case "NEW":
		return 2
	case "ACTIVE":
		return 1
	}
	return 0
}

// BuildTickets turns the week's scans into ticket input, from each scan's
// Open findings. An application is skipped - its ticket is never told it has
// nothing open - unless the open-findings lookup succeeded, the scan list
// identified it, and the scan was a complete, logged-in-as-configured
// vulnerability scan.
func BuildTickets(scans []ScanResult, owners Owners, now time.Time) TicketsFile {
	tf := TicketsFile{Generated: now.UTC()}
	for _, s := range scans {
		if s.NoNotification {
			continue // no scan this week that we were told about
		}
		key := AppKey(s)
		t := AppTicket{Key: key, App: s.App, AppID: s.AppID, Target: s.Target,
			PortalURL: s.PortalURL, Scanned: s.Finished, ScanLabel: s.Auth.Label()}
		if w, ok := owners.For(s.AppID, s.App); ok {
			t.Owner, t.Component, t.OwnerListed = w.Email, w.Component, true
			t.Watchers = w.Watchers
		}
		t.Covers = owners.CoversFor(s.AppID, s.App)
		switch {
		case strings.TrimSpace(s.AppID) == "":
			t.Skip = "the scan was not matched to an application in the scanner's scan list, so its findings could not be looked up reliably"
		case s.ScanType != "" && s.ScanType != "VULNERABILITY":
			t.Skip = "this week's scan was a " + strings.ToLower(s.ScanType) + " scan, which tests nothing"
		case s.Auth.Failed():
			t.Skip = "the scan's authentication failed, so it covered less of the application than it should - its findings are not trusted to say what is fixed"
		case !s.Complete:
			t.Skip = "the scan did not complete - its findings are not trusted to say what is fixed"
		case !s.OpenFetched:
			t.Skip = "the open findings could not be fetched from the scanner this week"
		}
		if t.Skip == "" {
			t.Findings, t.Lower = group(s.Open)
		}
		t.Hash = hashKeys(t.InstanceKeys())
		tf.Tickets = append(tf.Tickets, t)
	}
	sort.SliceStable(tf.Tickets, func(i, j int) bool { return tf.Tickets[i].App < tf.Tickets[j].App })
	return tf
}

func group(fs []Finding) ([]TicketFinding, int) {
	byID := map[string]*TicketFinding{}
	seen := map[string]bool{}
	lower := 0
	for _, f := range fs {
		if lowerActive(f) {
			lower++
			continue
		}
		if !ticketable(f) {
			continue
		}
		// Confirmed and potential instances of one QID are kept apart, so
		// a confirmed finding is never relabelled "unconfirmed" or the
		// reverse.
		gk := f.ID
		if f.Potential {
			gk = "potential|" + f.ID
		}
		g, ok := byID[gk]
		if !ok {
			g = &TicketFinding{ID: f.ID, Title: f.Title, Severity: f.Severity,
				Status: f.Status, FirstSeen: f.FirstSeen, Remedy: f.Remedy, Potential: f.Potential}
			byID[gk] = g
		}
		if f.Severity > g.Severity {
			g.Severity = f.Severity
		}
		if statusRank(f.Status) > statusRank(g.Status) {
			g.Status = f.Status
		}
		if !f.FirstSeen.IsZero() && (g.FirstSeen.IsZero() || f.FirstSeen.Before(g.FirstSeen)) {
			g.FirstSeen = f.FirstSeen
		}
		if g.Remedy == nil {
			g.Remedy = f.Remedy
		}
		ik := gk + "|" + f.URL + "|" + f.Param
		if seen[ik] {
			continue
		}
		seen[ik] = true
		g.Instances = append(g.Instances, Instance{URL: f.URL, Param: f.Param, Evidence: f.Evidence})
	}
	out := make([]TicketFinding, 0, len(byID))
	for _, g := range byID {
		sort.Slice(g.Instances, func(i, j int) bool {
			if g.Instances[i].URL != g.Instances[j].URL {
				return g.Instances[i].URL < g.Instances[j].URL
			}
			return g.Instances[i].Param < g.Instances[j].Param
		})
		if len(g.Instances) > maxInstances {
			g.More = len(g.Instances) - maxInstances
		}
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Potential != out[j].Potential {
			return !out[i].Potential // confirmed first
		}
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].ID < out[j].ID
	})
	return out, lower
}

func hashKeys(keys []string) string {
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// JSON is the file body.
func (tf TicketsFile) JSON() []byte {
	b, _ := json.MarshalIndent(tf, "", "  ")
	return append(b, '\n')
}
