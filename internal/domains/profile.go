package domains

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// WHAT EACH DOMAIN IS SUPPOSED TO LOOK LIKE
//
// The security team's decision chart, one profile per row, chosen by the
// markers on the domain's line in domains.txt. The profile says what MX, SPF,
// DKIM and DMARC the domain should publish; the difference between that and
// what DNS says today is a list of exact records for IT to set, filed as one
// Jira ticket per run (cmd/cti-jira --domains-actions), because every change
// needs the same GoDaddy admin access.
//
// Only the lock-down rows (3, 4/5, 9) get copy-paste records: what a domain
// that sends nothing should publish does not depend on anything we cannot see.
// Sending domains (1, 2, 6, 8) get records only where the answer is certain -
// a missing DMARC starts at p=none - and review items otherwise, because the
// right SPF depends on who really sends. Row 7 (senders unknown) is never
// tightened. Row 10 (SPF broken) is an overlay: fix SPF first, and no DMARC
// escalation is asked for until it is.

// Profile is one row of the chart.
type Profile int

const (
	ProfileActive        Profile = iota // 1. sends and receives
	ProfileSendOnly                     // 2. sends, receives nothing
	ProfileReceiveOnly                  // 3. receives, sends nothing
	ProfileNoMail                       // 4/5. no mail at all (parked, or website only)
	ProfileSaaS                         // 6. an application or service sends as it
	ProfileUnknown                      // 7. senders not fully known
	ProfileLegacyActive                 // 8. legacy brand that still sends and receives
	ProfileLegacyReceive                // 9. legacy brand, outbound moved to the main domain
)

// ProfileOf maps an inventory line's markers to a chart row.
func ProfileOf(e Entry) Profile {
	switch {
	case e.Unknown:
		return ProfileUnknown
	case e.SaaS:
		return ProfileSaaS
	case e.Sends && e.Receives && e.Legacy:
		return ProfileLegacyActive
	case e.Sends && e.Receives:
		return ProfileActive
	case e.Sends:
		return ProfileSendOnly
	case e.Receives && e.Legacy:
		return ProfileLegacyReceive
	case e.Receives:
		return ProfileReceiveOnly
	}
	return ProfileNoMail
}

func (p Profile) String() string {
	switch p {
	case ProfileActive:
		return "1. active mail domain"
	case ProfileSendOnly:
		return "2. send-only"
	case ProfileReceiveOnly:
		return "3. receive-only"
	case ProfileNoMail:
		return "4/5. no mail"
	case ProfileSaaS:
		return "6. application/SaaS sender"
	case ProfileUnknown:
		return "7. senders not known"
	case ProfileLegacyActive:
		return "8. legacy, still sends and receives"
	case ProfileLegacyReceive:
		return "9. legacy, receives only"
	}
	return "?"
}

// LockedDown reports whether the profile sends nothing: SPF -all and DMARC
// p=reject, with copy-paste records when they are wrong.
func (p Profile) LockedDown() bool {
	return p == ProfileReceiveOnly || p == ProfileNoMail || p == ProfileLegacyReceive
}

// Action is one change for IT: an exact record when Set is filled, a review
// item when it is not.
type Action struct {
	Domain  string `json:"domain"`
	Profile string `json:"profile"`
	Type    string `json:"type"`              // TXT, MX
	Host    string `json:"host"`              // @, _dmarc, selector._domainkey
	Set     string `json:"set,omitempty"`     // the value to publish; "" for a review item
	Replace string `json:"replace,omitempty"` // what is there now, when something is
	Delete  bool   `json:"delete,omitempty"`  // remove the record, publish nothing
	Why     string `json:"why"`
}

// Exact reports whether IT can apply the action without a decision.
func (a Action) Exact() bool { return a.Set != "" || a.Delete }

// Actions lists the changes every domain needs to match its profile.
// Lookups that failed produce nothing: an unknown is never a change request.
func Actions(results []Result, rua string) []Action {
	var out []Action
	for _, r := range results {
		out = append(out, actionsFor(r, rua)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Host < out[j].Host
	})
	return out
}

const lockedSPF = "v=spf1 -all"

func actionsFor(r Result, rua string) []Action {
	p := ProfileOf(r.Entry)
	d, m := r.Entry.Name, r.Mail
	var out []Action
	add := func(typ, host, set, replace, why string) {
		out = append(out, Action{Domain: d, Profile: p.String(), Type: typ, Host: host,
			Set: set, Replace: replace, Why: why})
	}
	own := m.DMARCFrom == "" || m.DMARCFrom == d
	current := func(l Lookup) string { return strings.Join(l.Values, " | ") }

	switch {
	case p == ProfileUnknown:
		return nil

	case p.LockedDown():
		// SPF: exactly one record, and it authorises nobody.
		if m.SPF.Known() {
			switch {
			case !m.SPF.Present():
				add("TXT", "@", lockedSPF, "", "sends no mail: say so, so receivers fail forgeries")
			case len(m.SPF.Values) > 1:
				add("TXT", "@", lockedSPF, current(m.SPF),
					"more than one SPF record is a permanent error; replace them all with one")
			case SPFAuthorises(m.SPF.Values[0]) || SPFAll(m.SPF.Values[0]) != "-all":
				add("TXT", "@", lockedSPF, current(m.SPF),
					"sends no mail, so SPF should authorise nobody")
			}
		}
		// DMARC p=reject on the domain's own record. An inherited reject from
		// the parent already covers a subdomain.
		if m.DMARC.Known() {
			switch {
			case !m.DMARC.Present():
				add("TXT", "_dmarc", dmarcRecord("", "reject", rua), "",
					"no DMARC: nothing tells receivers to refuse mail forged as this domain")
			case own && len(m.DMARC.Values) > 1:
				add("TXT", "_dmarc", dmarcRecord("", "reject", rua), current(m.DMARC),
					"more than one DMARC record: receivers ignore them all")
			default:
				pol := ParseDMARC(m.DMARC.Values[0])
				if pol.Effective(!own) != "reject" || (own && pol.PCT < 100) {
					old := ""
					if own {
						old = m.DMARC.Values[0]
					}
					add("TXT", "_dmarc", dmarcRecord(old, "reject", rua), old,
						"sends no mail, so DMARC should be p=reject")
				}
			}
		}
		// DKIM keys are not needed and only widen what can be signed.
		if !m.DKIM.Wildcard {
			for _, sel := range m.DKIM.Found {
				out = append(out, Action{Domain: d, Profile: p.String(), Type: "TXT",
					Host: sel + "._domainkey", Delete: true, Replace: "(published key)",
					Why: "sends no mail, so it needs no DKIM key"})
			}
		}
		// MX: keep it for the receive-only rows; prefer a null MX otherwise.
		if p == ProfileNoMail && m.MX.Known() && !isNullMX(m.MX) {
			why := "receives no mail: a null MX (RFC 7505) makes senders fail at once"
			if m.MX.Present() {
				why += " - CHECK no mailbox or alias uses this domain before replacing"
			}
			add("MX", "@", "0 .", current(m.MX), why)
		}

	default:
		// Sending rows. Exact only where the answer cannot depend on who sends.
		spfBroken := m.SPF.Known() && m.SPF.Present() &&
			(len(m.SPF.Values) > 1 || m.SPFLookups > 10 || SPFAll(m.SPF.Values[0]) == "+all")
		if spfBroken {
			add("TXT", "@", "", current(m.SPF), fmt.Sprintf(
				"SPF is broken (%s) - fix it first; DMARC enforcement waits until it is (chart row 10)",
				spfProblem(m)))
		} else if m.SPF.Known() && !m.SPF.Present() {
			add("TXT", "@", "", "", "sends mail but has no SPF - list the real senders (mail platform, "+
				"and any application or service), ending -all")
		}
		if m.DMARC.Known() && own {
			switch {
			case !m.DMARC.Present():
				add("TXT", "_dmarc", dmarcRecord("", "none", rua), "",
					"no DMARC: start at p=none to see who sends, then quarantine, then reject")
			case len(m.DMARC.Values) > 1:
				add("TXT", "_dmarc", "", current(m.DMARC),
					"more than one DMARC record: receivers ignore them all - merge into one")
			case !spfBroken:
				pol := ParseDMARC(m.DMARC.Values[0])
				if pol.P == "none" {
					add("TXT", "_dmarc", "", m.DMARC.Values[0],
						"DMARC is p=none: when the aggregate reports show only legitimate "+
							"senders, raise to p=quarantine, then p=reject")
				}
			}
		}
		if p == ProfileActive || p == ProfileLegacyActive {
			if m.MX.Known() && (!m.MX.Present() || isNullMX(m.MX)) {
				add("MX", "@", "", current(m.MX), "receives mail but has no working MX")
			}
		}
	}
	return out
}

func isNullMX(l Lookup) bool { return len(l.Values) == 1 && l.Values[0] == "." }

func spfProblem(m Mail) string {
	switch {
	case len(m.SPF.Values) > 1:
		return fmt.Sprintf("%d records", len(m.SPF.Values))
	case m.SPFLookups > 10:
		return fmt.Sprintf("%d DNS lookups, over the limit of 10", m.SPFLookups)
	}
	return "+all authorises every host"
}

// dmarcRecord sets p= on an existing record, keeping its other tags, or
// builds a new one. rua is added when the record has none and one is known.
func dmarcRecord(existing, policy, rua string) string {
	tags := []string{"v=DMARC1", "p=" + policy}
	hasRUA := false
	for _, part := range strings.Split(existing, ";") {
		k, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "v", "p", "pct":
			// pct below 100 applies the policy to part of the mail only;
			// a rewritten record applies it to all of it.
			continue
		case "rua":
			hasRUA = true
		}
		tags = append(tags, strings.TrimSpace(part))
	}
	if !hasRUA && strings.TrimSpace(rua) != "" {
		r := strings.TrimSpace(rua)
		if !strings.HasPrefix(strings.ToLower(r), "mailto:") {
			r = "mailto:" + r
		}
		tags = append(tags, "rua="+r)
	}
	return strings.Join(tags, "; ")
}

// ActionsHash identifies a set of actions, so an unchanged list is not
// re-posted to the open ticket every week.
func ActionsHash(a []Action) string {
	h := sha256.New()
	for _, x := range a {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%t\n", x.Domain, x.Type, x.Host, x.Set, x.Delete)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ActionsFile is what cti-domains --actions-out writes and cti-jira
// --domains-actions reads: this run's changes, and their hash so an
// unchanged list is not re-posted.
type ActionsFile struct {
	Generated string   `json:"generated"`
	Hash      string   `json:"hash"`
	Domains   int      `json:"domains"` // how many domains need something
	Exact     int      `json:"exact"`   // copy-paste records
	Review    int      `json:"review"`  // items that need a decision
	Actions   []Action `json:"actions"`
}

// NewActionsFile summarises a run's actions.
func NewActionsFile(now time.Time, a []Action) ActionsFile {
	f := ActionsFile{Generated: now.UTC().Format(time.RFC3339), Hash: ActionsHash(a), Actions: a}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x.Domain] = true
		if x.Exact() {
			f.Exact++
		} else {
			f.Review++
		}
	}
	f.Domains = len(seen)
	if f.Actions == nil {
		f.Actions = []Action{}
	}
	return f
}

// JSON is the file's bytes.
func (f ActionsFile) JSON() []byte {
	b, _ := json.MarshalIndent(f, "", "  ")
	return append(b, '\n')
}

// ActionsCSV is the ticket's attachment: one row per change, ready to work
// through in a spreadsheet.
func ActionsCSV(a []Action) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"domain", "chart_row", "type", "host", "action", "set_to", "current", "why"})
	for _, x := range a {
		act := "review"
		switch {
		case x.Delete:
			act = "delete"
		case x.Set != "" && x.Replace != "":
			act = "replace"
		case x.Set != "":
			act = "add"
		}
		row := []string{x.Domain, x.Profile, x.Type, x.Host, act, x.Set, x.Replace, x.Why}
		for i := range row {
			row[i] = cell(row[i])
		}
		_ = w.Write(row)
	}
	w.Flush()
	return buf.Bytes()
}

// ActionLine is one action in words, for the report and the ticket.
func ActionLine(x Action) string {
	switch {
	case x.Delete:
		return fmt.Sprintf("delete %s %s - %s", x.Type, x.Host, x.Why)
	case x.Set != "" && x.Replace != "":
		return fmt.Sprintf("%s %s: replace %q with %q - %s", x.Type, x.Host, x.Replace, x.Set, x.Why)
	case x.Set != "":
		return fmt.Sprintf("%s %s: add %q - %s", x.Type, x.Host, x.Set, x.Why)
	}
	return fmt.Sprintf("%s %s: REVIEW - %s", x.Type, x.Host, x.Why)
}
