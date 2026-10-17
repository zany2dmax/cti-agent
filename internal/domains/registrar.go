package domains

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Registration is one domain as the registrar holds it.
type Registration struct {
	Domain    string
	Status    string // ACTIVE, CANCELLED, PENDING_TRANSFER, ...
	Expires   time.Time
	AutoRenew bool
	// Locked is the registrar transfer lock. Off means the domain can be
	// transferred away with an auth code - the step a hijack needs.
	Locked      bool
	Privacy     bool
	NameServers []string // lower-case, no trailing dot, sorted
}

// Registrar lists the domains an account holds.
//
// An interface for the same reason internal/vulnlookup and internal/appscan
// are: GoDaddy today, and moving registrar - or holding domains at two -
// should be an implementation, not a rewrite.
type Registrar interface {
	Name() string
	Domains(ctx context.Context) ([]Registration, error)
}

// Comparison is the inventory file against the registrar account.
type Comparison struct {
	// Registrar is the account compared against, e.g. "godaddy".
	Registrar string
	// Covered maps an inventory name to the registration that covers it - the
	// domain itself, or its parent for a subdomain entry.
	Covered map[string]Registration
	// NotAtRegistrar are inventory entries no registration covers: held at
	// another registrar, lapsed, or not ours at all. Each is a question
	// somebody should be able to answer.
	NotAtRegistrar []Entry
	// NotInInventory are registrations the inventory does not list. The
	// account owns them and nobody is checking them - which is the gap this
	// list exists to close.
	NotInInventory []Registration
	// Lapsed are inventory entries whose registration was cancelled or ran
	// out long ago (see Registration.Lapsed): no longer ours, so they are
	// listed once for removal from domains.txt and not probed at all.
	Lapsed []LapsedEntry
	// LapsedUnlisted counts lapsed registrations the inventory does not list
	// either: account history, not work, so they are not reported.
	LapsedUnlisted int
}

// LapsedEntry is an inventory line whose registration is gone.
type LapsedEntry struct {
	Entry Entry
	Reg   Registration
}

// lapsedAfter is how long past expiry a cancelled or expired registration
// must be before it is history rather than an emergency. Inside it the
// domain may still be in the registrar's grace or redemption period, and a
// domain that lapsed by accident last week is exactly what this lane is for.
const lapsedAfter = 45 * 24 * time.Hour

// Lapsed reports whether the registration is gone for good: cancelled,
// expired or transferred out, and (when the expiry is known) more than
// lapsedAfter ago. GoDaddy keeps such registrations in the account listing
// for years; reporting "no nameservers" and "expired 2013" on them every
// week is noise nobody can act on.
func (r Registration) Lapsed(now time.Time) bool {
	s := strings.ToUpper(strings.TrimSpace(r.Status))
	gone := strings.HasPrefix(s, "CANCELLED") || s == "EXPIRED" || s == "TRANSFERRED_OUT"
	if !gone {
		return false
	}
	return r.Expires.IsZero() || now.Sub(r.Expires) > lapsedAfter
}

// SetAsideLapsed moves lapsed registrations out of the comparison: inventory
// entries they cover go to Lapsed (and out of Covered), and unlisted ones are
// only counted. It returns the names of the lapsed inventory entries, which
// the caller leaves out of the probe.
func (c *Comparison) SetAsideLapsed(now time.Time) map[string]bool {
	gone := map[string]bool{}
	names := make([]string, 0, len(c.Covered))
	for n := range c.Covered {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		reg := c.Covered[n]
		if !reg.Lapsed(now) {
			continue
		}
		c.Lapsed = append(c.Lapsed, LapsedEntry{Entry: Entry{Name: n}, Reg: reg})
		delete(c.Covered, n)
		gone[n] = true
	}
	var keep []Registration
	for _, r := range c.NotInInventory {
		if r.Lapsed(now) {
			c.LapsedUnlisted++
			continue
		}
		keep = append(keep, r)
	}
	c.NotInInventory = keep
	return gone
}

// Compare matches the inventory with the account.
func Compare(registrar string, inv []Entry, regs []Registration) Comparison {
	c := Comparison{Registrar: registrar, Covered: map[string]Registration{}}

	// Longest registration first, so a subdomain entry is matched to the most
	// specific registration when the account holds both a parent and a child.
	sorted := append([]Registration(nil), regs...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Domain) > len(sorted[j].Domain) })

	used := map[string]bool{}
	for _, e := range inv {
		matched := false
		for _, r := range sorted {
			if coveredBy(e.Name, r.Domain) {
				c.Covered[e.Name] = r
				used[r.Domain] = true
				matched = true
				break
			}
		}
		if !matched {
			c.NotAtRegistrar = append(c.NotAtRegistrar, e)
		}
	}
	for _, r := range regs {
		if !used[r.Domain] {
			c.NotInInventory = append(c.NotInInventory, r)
		}
	}
	sort.Slice(c.NotInInventory, func(i, j int) bool {
		return c.NotInInventory[i].Domain < c.NotInInventory[j].Domain
	})
	return c
}

// cleanHost lower-cases a DNS name and drops the trailing dot.
func cleanHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// cleanHosts is cleanHost over a list, de-duplicated and sorted, so two runs
// that see the same records compare equal.
func cleanHosts(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if h := cleanHost(s); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// CleanHosts is cleanHosts for providers outside this package.
func CleanHosts(in []string) []string { return cleanHosts(in) }
