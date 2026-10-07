package domains

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// State is last week's observations, for the week-over-week diff.
//
// # WHAT IS DIFFED, AND WHAT IS NOT
//
// Nameservers, MX, SPF, DMARC, CNAME targets, live/parked, certificate issuer
// and the registrar's own fields. These change rarely and on purpose, so a
// change nobody planned is worth a line: a nameserver swap is how a domain
// hijack looks from the outside.
//
// NOT address records. A site behind a CDN changes A records constantly, and
// a diff that fires every week trains its readers to skip the section.
//
// A field whose lookup FAILED this week keeps last week's value rather than
// being recorded as empty. Otherwise one resolver timeout produces "MX
// removed" this week and "MX added" next week - two false changes from one
// non-event.
type State struct {
	Version int                 `json:"version"`
	Taken   time.Time           `json:"taken"`
	Domains map[string]Snapshot `json:"domains"`
	// Registrations is the account's domain list when the registrar was
	// consulted; nil when it was not, so a skipped registrar check is not
	// read next week as every domain having left the account.
	Registrations []string `json:"registrations,omitempty"`
}

// Snapshot is one domain. Multi-valued fields are space-joined and sorted;
// "" means absent.
type Snapshot struct {
	NS    string              `json:"ns,omitempty"`
	MX    string              `json:"mx,omitempty"`
	SPF   string              `json:"spf,omitempty"`
	DMARC string              `json:"dmarc,omitempty"`
	Hosts map[string]HostSnap `json:"hosts,omitempty"`
	Reg   *RegSnap            `json:"reg,omitempty"`
}

// HostSnap is one probed host.
type HostSnap struct {
	CNAME  string `json:"cname,omitempty"`
	Live   bool   `json:"live"`
	Parked bool   `json:"parked"`
	Issuer string `json:"issuer,omitempty"`
}

// RegSnap is the registrar's view.
type RegSnap struct {
	Status    string `json:"status"`
	NS        string `json:"ns,omitempty"`
	Locked    bool   `json:"locked"`
	AutoRenew bool   `json:"autoRenew"`
}

const stateVersion = 1

// LoadState reads the state file. A missing file is an empty state (first
// run); a corrupt one is an error, because silently starting over would
// report no changes in a week that may have had them.
func LoadState(path string) (*State, error) {
	// #nosec G304 -- path is --state, defaulting to $FLEET_HOME/state; set by
	// the unit or the operator, never by anything the lane reads from outside.
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is not valid state JSON (%w) - move it aside to start over", path, err)
	}
	return &s, nil
}

// SaveState writes atomically, 0600: it lists every domain and its records.
func SaveState(path string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".domains-state-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func joinLookup(l Lookup, prev string) string {
	if !l.Known() {
		return prev
	}
	v := append([]string(nil), l.Values...)
	sort.Strings(v)
	return strings.Join(v, " ")
}

// Snap builds this week's state, carrying forward fields that failed.
func Snap(now time.Time, results []Result, cmp *Comparison, regs []Registration, prev *State) *State {
	s := &State{Version: stateVersion, Taken: now.UTC(), Domains: map[string]Snapshot{}}
	for _, r := range results {
		var p Snapshot
		if prev != nil {
			p = prev.Domains[r.Entry.Name]
		}
		sn := Snapshot{
			NS:    joinLookup(r.NS, p.NS),
			MX:    joinLookup(r.Mail.MX, p.MX),
			SPF:   joinLookup(r.Mail.SPF, p.SPF),
			DMARC: joinLookup(r.Mail.DMARC, p.DMARC),
			Hosts: map[string]HostSnap{},
		}
		for _, w := range r.Web {
			if !w.Addrs.Known() {
				if old, ok := p.Hosts[w.Host]; ok {
					sn.Hosts[w.Host] = old
				}
				continue
			}
			h := HostSnap{CNAME: w.CNAME, Live: w.Live(), Parked: w.ParkedBy() != "", Issuer: w.TLS.Issuer}
			if h.Issuer == "" && w.Live() {
				h.Issuer = p.Hosts[w.Host].Issuer // a failed dial is not a CA change
			}
			sn.Hosts[w.Host] = h
		}
		if cmp != nil {
			if reg, ok := cmp.Covered[r.Entry.Name]; ok && reg.Domain == r.Entry.Name {
				sn.Reg = &RegSnap{Status: reg.Status, NS: strings.Join(reg.NameServers, " "),
					Locked: reg.Locked, AutoRenew: reg.AutoRenew}
			}
		} else {
			sn.Reg = p.Reg
		}
		s.Domains[r.Entry.Name] = sn
	}
	if cmp != nil {
		for _, r := range regs {
			s.Registrations = append(s.Registrations, r.Domain)
		}
		sort.Strings(s.Registrations)
	} else if prev != nil {
		s.Registrations = prev.Registrations
	}
	return s
}

// Diff compares this week with last. Nothing on the first run.
func Diff(prev, cur *State, registrarChecked bool, registrar string) []Finding {
	if prev == nil || cur == nil {
		return nil
	}
	var out []Finding
	add := func(d string, s Severity, f string, a ...any) {
		out = append(out, Finding{Domain: d, Sev: s, Area: "change", Text: fmt.Sprintf(f, a...)})
	}
	field := func(d, name, was, now string, sev Severity) {
		if was == now {
			return
		}
		switch {
		case was == "":
			add(d, sev, "%s appeared: %s", name, now)
		case now == "":
			add(d, sev, "%s removed (was %s)", name, was)
		default:
			add(d, sev, "%s changed from %s to %s", name, was, now)
		}
	}

	names := make([]string, 0, len(cur.Domains))
	for d := range cur.Domains {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		c := cur.Domains[d]
		p, ok := prev.Domains[d]
		if !ok {
			continue // new to the inventory: nothing to compare with
		}
		field(d, "nameservers", p.NS, c.NS, High)
		field(d, "MX", p.MX, c.MX, Medium)
		field(d, "SPF", p.SPF, c.SPF, Medium)
		field(d, "DMARC", p.DMARC, c.DMARC, Medium)
		hosts := make([]string, 0, len(c.Hosts))
		for h := range c.Hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		for _, h := range hosts {
			ch, ph := c.Hosts[h], p.Hosts[h]
			if _, had := p.Hosts[h]; !had {
				continue
			}
			field(d, h+" CNAME", ph.CNAME, ch.CNAME, Medium)
			if ph.Live != ch.Live {
				if ch.Live {
					add(d, Medium, "%s started serving a working page (2xx/3xx)", h)
				} else {
					add(d, Medium, "%s no longer serves a working page (2xx/3xx)", h)
				}
			}
			if ph.Live && ch.Live && ph.Parked != ch.Parked {
				if ch.Parked {
					add(d, Medium, "%s now serves a parking page", h)
				} else {
					add(d, Info, "%s no longer serves a parking page", h)
				}
			}
			if ph.Issuer != "" && ch.Issuer != "" {
				field(d, h+" certificate issuer", ph.Issuer, ch.Issuer, Info)
			}
		}
		if p.Reg != nil && c.Reg != nil && registrarChecked {
			field(d, registrar+" status", p.Reg.Status, c.Reg.Status, High)
			field(d, registrar+" nameservers", p.Reg.NS, c.Reg.NS, High)
			if p.Reg.Locked && !c.Reg.Locked {
				add(d, High, "transfer lock was switched OFF since last week")
			}
			if p.Reg.AutoRenew && !c.Reg.AutoRenew {
				add(d, Medium, "auto-renew was switched OFF since last week")
			}
		}
	}

	// A domain that left the account is the loudest change there is: lapsed,
	// transferred, or taken. Only when BOTH weeks consulted the registrar.
	if registrarChecked && prev.Registrations != nil {
		now := map[string]bool{}
		for _, r := range cur.Registrations {
			now[r] = true
		}
		for _, r := range prev.Registrations {
			if !now[r] {
				add(r, High, "no longer in the %s account (it was last week) - lapsed, "+
					"transferred out, or moved to another account", registrar)
			}
		}
	}
	SortFindings(out)
	return out
}
