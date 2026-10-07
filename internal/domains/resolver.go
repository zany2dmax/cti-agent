package domains

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
)

// Resolver is the slice of *net.Resolver the probe uses. net.DefaultResolver
// satisfies it; tests supply a map.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// Lookup is one DNS answer, and which of THREE outcomes it was.
//
// The original checker treated every lookup error as "no record". That turns
// a resolver timeout into "this domain has no DMARC", which is a High finding
// about a domain that may be perfectly configured. So:
//
//	Values set          the records
//	Absent              the name or record type does not exist - a fact
//	Err set             the lookup failed - we do not know, and must say so
type Lookup struct {
	Values []string
	Absent bool
	Err    string
}

// Known reports whether the lookup produced an answer, present or absent.
func (l Lookup) Known() bool { return l.Err == "" }

// Present reports whether there are records.
func (l Lookup) Present() bool { return len(l.Values) > 0 }

// classify turns a lookup error into Absent or Err.
func classify(err error) Lookup {
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return Lookup{Absent: true}
	}
	return Lookup{Err: errText(err)}
}

func errText(err error) string {
	s := err.Error()
	// The resolver's address is noise in a report and identifies the host.
	if i := strings.Index(s, " on "); i > 0 && strings.Contains(s[i:], ":53") {
		s = s[:i]
	}
	return s
}

func lookupTXT(ctx context.Context, r Resolver, name string) Lookup {
	v, err := r.LookupTXT(ctx, name)
	if err != nil {
		return classify(err)
	}
	if len(v) == 0 {
		return Lookup{Absent: true}
	}
	return Lookup{Values: v}
}

func lookupHost(ctx context.Context, r Resolver, name string) Lookup {
	v, err := r.LookupHost(ctx, name)
	if err != nil {
		return classify(err)
	}
	if len(v) == 0 {
		return Lookup{Absent: true}
	}
	sort.Strings(v)
	return Lookup{Values: v}
}

func lookupNS(ctx context.Context, r Resolver, name string) Lookup {
	v, err := r.LookupNS(ctx, name)
	if err != nil {
		return classify(err)
	}
	var hosts []string
	for _, ns := range v {
		hosts = append(hosts, ns.Host)
	}
	hosts = cleanHosts(hosts)
	if len(hosts) == 0 {
		return Lookup{Absent: true}
	}
	return Lookup{Values: hosts}
}

// lookupMX returns hosts in preference order. A null MX (RFC 7505, a single
// record whose host is ".") comes back as the one value ".".
func lookupMX(ctx context.Context, r Resolver, name string) Lookup {
	v, err := r.LookupMX(ctx, name)
	if err != nil {
		return classify(err)
	}
	sort.SliceStable(v, func(i, j int) bool { return v[i].Pref < v[j].Pref })
	var hosts []string
	for _, mx := range v {
		h := strings.ToLower(strings.TrimSpace(mx.Host))
		if h != "." {
			h = strings.TrimSuffix(h, ".")
		}
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return Lookup{Absent: true}
	}
	return Lookup{Values: hosts}
}
