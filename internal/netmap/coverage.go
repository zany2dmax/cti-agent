package netmap

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
)

// Range is an inclusive IPv4 address range.
type Range struct{ Lo, Hi uint32 }

func addrU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// PrefixRange is the range a network covers.
func PrefixRange(p netip.Prefix) Range {
	p = p.Masked()
	lo := addrU32(p.Addr())
	// The host bits all set. A shift of 32 on a uint32 is 0 in Go, so a /32
	// gives hi == lo and a /0 gives the whole space, with no widening to 64
	// bits and back.
	return Range{lo, lo | (math.MaxUint32 >> uint(p.Bits()))}
}

// ParseRange reads one Qualys IP-set entry: an address or "a.b.c.d-e.f.g.h".
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := netip.ParseAddr(strings.TrimSpace(lo))
	if err != nil || !a.Is4() {
		return Range{}, fmt.Errorf("%q is not an IPv4 address or range", s)
	}
	if !isRange {
		u := addrU32(a)
		return Range{u, u}, nil
	}
	b, err := netip.ParseAddr(strings.TrimSpace(hi))
	if err != nil || !b.Is4() || addrU32(b) < addrU32(a) {
		return Range{}, fmt.Errorf("%q is not an IPv4 address or range", s)
	}
	return Range{addrU32(a), addrU32(b)}, nil
}

// Merge sorts ranges and joins the ones that touch or overlap.
func Merge(in []Range) []Range {
	if len(in) == 0 {
		return nil
	}
	r := append([]Range(nil), in...)
	sort.Slice(r, func(i, j int) bool { return r[i].Lo < r[j].Lo })
	out := []Range{r[0]}
	for _, x := range r[1:] {
		last := &out[len(out)-1]
		if uint64(x.Lo) <= uint64(last.Hi)+1 {
			if x.Hi > last.Hi {
				last.Hi = x.Hi
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

// state says how much of target the merged ranges cover.
type state int

const (
	none state = iota
	partial
	full
)

func coverage(merged []Range, target Range) state {
	var got uint64
	for _, r := range merged {
		lo, hi := r.Lo, r.Hi
		if hi < target.Lo || lo > target.Hi {
			continue
		}
		if lo < target.Lo {
			lo = target.Lo
		}
		if hi > target.Hi {
			hi = target.Hi
		}
		got += uint64(hi) - uint64(lo) + 1
	}
	want := uint64(target.Hi) - uint64(target.Lo) + 1
	switch {
	case got == 0:
		return none
	case got >= want:
		return full
	}
	return partial
}

// Group is a Qualys Asset Group: its title and the addresses it holds.
type Group struct {
	ID     string
	Title  string
	Ranges []Range
}

// Kind is what a finding says.
type Kind string

const (
	// NotInAnyGroup: a corp network in the spreadsheet that no Asset Group
	// holds. This is the one that means a location was missed.
	NotInAnyGroup Kind = "not-in-any-group"
	// GroupNotScanned: held by an Asset Group, but not by one of the scans'
	// Target Groups.
	GroupNotScanned Kind = "group-not-scanned"
	// PartlyCovered: only part of the network is in the scanned groups.
	PartlyCovered Kind = "partly-covered"
	// ScannedNotInSheet: a scanned Asset Group whose addresses appear nowhere in
	// the spreadsheet.
	ScannedNotInSheet Kind = "scanned-not-in-sheet"
	// UnknownTargetGroup: a scan names a Target Group Qualys has no Asset Group
	// of that title for.
	UnknownTargetGroup Kind = "unknown-target-group"
)

// Finding is one thing the check found.
type Finding struct {
	Kind     Kind
	Location string
	Subnet   string
	Group    string
	Detail   string
	// Row is the spreadsheet row of the network, zero for a finding about a
	// Qualys group.
	Row int
}

// Result is the check's output.
type Result struct {
	Findings []Finding
	// Checked is how many corp networks were compared.
	Checked int
	// Covered is how many of them are fully inside the scanned groups.
	Covered int
}

func titleKey(s string) string {
	return normKey(strings.NewReplacer("\ufeff", "", "\u200b", "", "\u00a0", " ").Replace(s))
}

// Check compares the spreadsheet's corp networks (and all of its networks) with
// the Asset Groups, given which Target Groups the scans cover.
//
// Compared by address, with ranges merged, so a /24 split across two groups
// counts as covered and a group that holds only half of one is called partial.
func Check(corp []Corp, all []Subnet, groups []Group, scanned []string) Result {
	byTitle := map[string]Group{}
	for _, g := range groups {
		byTitle[titleKey(g.Title)] = g
	}
	var res Result

	// Which groups the scans actually target.
	scannedGroups := map[string]Group{}
	var scannedRanges, allRanges []Range
	for _, t := range scanned {
		g, ok := byTitle[titleKey(t)]
		if !ok {
			res.Findings = append(res.Findings, Finding{Kind: UnknownTargetGroup, Group: t,
				Detail: "a scan covers this Target Group but Qualys lists no Asset Group with that title"})
			continue
		}
		scannedGroups[titleKey(g.Title)] = g
		scannedRanges = append(scannedRanges, g.Ranges...)
	}
	for _, g := range groups {
		allRanges = append(allRanges, g.Ranges...)
	}
	mScanned, mAll := Merge(scannedRanges), Merge(allRanges)

	for _, c := range corp {
		res.Checked++
		t := PrefixRange(c.Subnet.Prefix)
		switch coverage(mScanned, t) {
		case full:
			res.Covered++
			continue
		case partial:
			res.Findings = append(res.Findings, Finding{Kind: PartlyCovered, Location: c.Location,
				Subnet: c.Subnet.Prefix.String(), Row: c.Subnet.Row, Detail: "only part of this network is in the groups the scans cover"})
			continue
		}
		switch coverage(mAll, t) {
		case none:
			res.Findings = append(res.Findings, Finding{Kind: NotInAnyGroup, Location: c.Location,
				Subnet: c.Subnet.Prefix.String(), Row: c.Subnet.Row, Detail: "no Asset Group holds this network"})
		default:
			var in []string
			for _, g := range groups {
				if coverage(Merge(g.Ranges), t) != none {
					in = append(in, g.Title)
				}
			}
			res.Findings = append(res.Findings, Finding{Kind: GroupNotScanned, Location: c.Location,
				Subnet: c.Subnet.Prefix.String(), Row: c.Subnet.Row, Group: strings.Join(in, ", "),
				Detail: "held by an Asset Group that no scan covers"})
		}
	}

	// A scanned group whose addresses appear nowhere in the spreadsheet.
	var sheet []Range
	for _, s := range all {
		if s.Valid {
			sheet = append(sheet, PrefixRange(s.Prefix))
		}
	}
	mSheet := Merge(sheet)
	var keys []string
	for k := range scannedGroups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := scannedGroups[k]
		if len(g.Ranges) == 0 {
			res.Findings = append(res.Findings, Finding{Kind: ScannedNotInSheet, Group: g.Title,
				Detail: "this Asset Group holds no IP ranges, so it cannot be checked"})
			continue
		}
		found := false
		for _, r := range g.Ranges {
			if coverage(mSheet, r) != none {
				found = true
				break
			}
		}
		if !found {
			res.Findings = append(res.Findings, Finding{Kind: ScannedNotInSheet, Group: g.Title,
				Detail: "none of this scanned group's addresses appear in the spreadsheet"})
		}
	}
	return res
}
