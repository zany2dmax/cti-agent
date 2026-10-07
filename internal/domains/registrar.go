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
