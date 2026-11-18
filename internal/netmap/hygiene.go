package netmap

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/xlsx"
)

// # CLEAN-UP: WHAT IS WRONG IN THE SHEET BUT DOES NOT STOP THE CHECK
//
// The questions (rules.go) are the rows the coverage check cannot read, so
// the location goes unchecked until they are fixed. These are the rest: the
// sheet is still readable, but something in it is wrong, unclear or
// inconsistent - a misspelled DECOMMISSIONED, a row that belongs to no
// location's block, two locations claiming the same network, the same public
// IP under two sites. They go to the network team in the same ticket, in a
// section of their own, because the spreadsheet is theirs (the security team
// only reads it). Like the questions, they say what is wrong and where, and
// never ask the security team to work around it.

// CleanupKind classifies a clean-up item.
type CleanupKind string

const (
	CMisspelledDecom CleanupKind = "misspelled-decommissioned"
	CDecomMention    CleanupKind = "decommission-not-at-start"
	CUnsure          CleanupKind = "header-unsure"
	CNoBlock         CleanupKind = "header-no-block"
	COutsideRows     CleanupKind = "rows-outside-block"
	COverlapRows     CleanupKind = "rows-overlap"
	CBlankRows       CleanupKind = "rows-no-network"
	CSharedPublicIP  CleanupKind = "shared-public-ip"
	CNote            CleanupKind = "note"
)

// Cleanup is one thing the network team should tidy.
type Cleanup struct {
	Location string
	Row      int
	Kind     CleanupKind
	Why      string
}

// CleanupOrder is the order the kinds are listed in.
var CleanupOrder = []CleanupKind{CNote, COverlapRows, COutsideRows, CSharedPublicIP, CMisspelledDecom,
	CDecomMention, CUnsure, CNoBlock, CBlankRows}

// CleanupTitle is a kind's heading.
func CleanupTitle(k CleanupKind) string {
	switch k {
	case CNote:
		return "Checked against other records"
	case COverlapRows:
		return "Networks claimed by two locations"
	case COutsideRows:
		return "Networks outside their location's own block"
	case CSharedPublicIP:
		return "The same public IP under two locations"
	case CMisspelledDecom:
		return "DECOMMISSIONED misspelled"
	case CDecomMention:
		return "Header mentions a decommissioning but does not start with it"
	case CUnsure:
		return "Header marked as unsure"
	case CNoBlock:
		return "Header without the location's /16 block"
	default:
		return "Rows with a VLAN but no network"
	}
}

// CleanupAction is what the network team is asked to do for a kind.
func CleanupAction(k CleanupKind) string {
	switch k {
	case CNote:
		return "Network team: check the sheet against the record named, and correct whichever is wrong."
	case COverlapRows:
		return "Network team: two locations list overlapping networks; correct the one that is wrong."
	case COutsideRows:
		return "Network team: these rows are outside the block in the location's header; correct the row or the header."
	case CSharedPublicIP:
		return "Network team: two sites rarely share a public IP; correct the one copied from the other."
	case CMisspelledDecom:
		return "Network team: spell it DECOMMISSIONED, so the location reads as closed."
	case CDecomMention:
		return "Network team: if the location is open, reword the header without the word; if it is closed, start the header with DECOMMISSIONED."
	case CUnsure:
		return "Network team: say whether the location is open, and remove the question marks."
	case CNoBlock:
		return "Network team: end the header with the location's /16 block, for example \"Example Site - ST - 10.4.0.0/16\"."
	default:
		return "Network team: fill in the network, or remove the row if the VLAN is not used."
	}
}

var (
	ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// locationHead is one location as the hygiene checks see it.
type locationHead struct {
	name   string
	row    int
	active bool
	blocks []netip.Prefix
	subs   []Subnet
}

// Hygiene lists the clean-up items in the sheet. rows are the sheet's rows
// (for the public IPs, which the subnet parser skips), subs its parsed
// networks, and qs the questions already asked, so nothing is said twice.
func Hygiene(rows []xlsx.Row, subs []Subnet, qs []Question) []Cleanup {
	var heads []*locationHead
	byName := map[string]*locationHead{}
	for _, s := range subs {
		h := byName[s.Location]
		if h == nil {
			h = &locationHead{name: s.Location, row: s.LocRow, blocks: headerBlocks(s.Location)}
			byName[s.Location] = h
			heads = append(heads, h)
		}
		h.subs = append(h.subs, s)
		if !s.Inactive {
			h.active = true
		}
	}
	asked := map[string]bool{}
	for _, q := range qs {
		asked[q.Location+"|"+string(q.Kind)] = true
	}

	var out []Cleanup
	add := func(loc string, row int, k CleanupKind, f string, a ...any) {
		out = append(out, Cleanup{Location: loc, Row: row, Kind: k, Why: fmt.Sprintf(f, a...)})
	}
	for _, h := range heads {
		l := strings.ToLower(strings.TrimSpace(h.name))
		switch {
		case strings.HasPrefix(l, "decom") && !strings.HasPrefix(l, "decommission"):
			add(h.name, h.row, CMisspelledDecom, "the header starts with %q", strings.Fields(h.name)[0])
		case !strings.HasPrefix(l, "decom") && (strings.Contains(l, "decommission") || strings.Contains(l, "decomission")):
			add(h.name, h.row, CDecomMention, "the header mentions a decommissioning, but the location is read as open")
		}
		if strings.Contains(h.name, "??") {
			add(h.name, h.row, CUnsure, "the header has \"??\" in it")
		}
		if !h.active {
			continue // a closed location's rows are not worth tidying
		}
		switch {
		case len(h.blocks) == 0:
			add(h.name, h.row, CNoBlock, "the header names no network block")
		case h.blocks[0].Bits() > 16:
			add(h.name, h.row, CNoBlock, "the header names %s, not the location's /16", h.blocks[0])
		}
		// Rows outside the header's block. 10.x only: a 192.168 or 172.16
		// network under a site (HQ's corp, a datacenter's servers) is a
		// different addressing plan, not a typo.
		if len(h.blocks) > 0 && !asked[h.name+"|"+string(QOutside)] {
			var stray []string
			row := 0
			for _, s := range h.subs {
				if s.Inactive || !s.Valid || s.Prefix.Addr().As4()[0] != 10 || within(h.blocks, s.Prefix) {
					continue
				}
				stray = append(stray, fmt.Sprintf("%s (%s)", s.Prefix, s.Role))
				if row == 0 {
					row = s.Row
				}
			}
			if len(stray) > 0 {
				add(h.name, row, COutsideRows, "outside %s: %s", headerBlockList(h.blocks), strings.Join(stray, ", "))
			}
		}
		// Rows with a VLAN but no network (the corp row is a question already).
		var blank []string
		row := 0
		for _, s := range h.subs {
			if s.Inactive || s.Valid || strings.TrimSpace(s.Raw) != "" || strings.EqualFold(s.Role, "corp") {
				continue
			}
			blank = append(blank, s.Role)
			if row == 0 {
				row = s.Row
			}
		}
		if len(blank) > 0 {
			add(h.name, row, CBlankRows, "no network written for: %s", strings.Join(dedupe(blank), ", "))
		}
	}

	// Networks two active locations both claim, beyond the corp rows the
	// questions already cover. One line per pair of locations.
	seenPair := map[string]bool{}
	for i, a := range heads {
		if !a.active {
			continue
		}
		for _, b := range heads[i+1:] {
			if !b.active {
				continue
			}
			var hits []string
			row := 0
			for _, x := range a.subs {
				if x.Inactive || !x.Valid {
					continue
				}
				for _, y := range b.subs {
					if y.Inactive || !y.Valid || !x.Prefix.Overlaps(y.Prefix) {
						continue
					}
					if strings.EqualFold(x.Role, "corp") && strings.EqualFold(y.Role, "corp") {
						continue // a QOverlap question
					}
					hits = append(hits, fmt.Sprintf("%s (%s) and %s (%s)", x.Prefix, x.Role, y.Prefix, y.Role))
					if row == 0 {
						row = x.Row
					}
				}
			}
			key := a.name + "|" + b.name
			if len(hits) > 0 && !seenPair[key] {
				seenPair[key] = true
				add(a.name, row, COverlapRows, "overlaps %s: %s", b.name, strings.Join(hits, "; "))
			}
		}
	}

	// The same public IP under two active locations.
	ips := publicIPs(rows)
	var keys []string
	for ip := range ips {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	for _, ip := range keys {
		var locs []string
		row := 0
		for _, p := range ips[ip] {
			if h := byName[p.loc]; h != nil && h.active {
				locs = append(locs, p.loc)
				if row == 0 {
					row = p.row
				}
			}
		}
		locs = dedupe(locs)
		if len(locs) > 1 {
			add(locs[0], row, CSharedPublicIP, "public IP %s is also listed under %s", ip, strings.Join(locs[1:], ", "))
		}
	}
	return out
}

type ipAt struct {
	loc string
	row int
}

// publicIPs is the internet rows' addresses by location, following the same
// header rules as ParseSiteRows.
func publicIPs(rows []xlsx.Row) map[string][]ipAt {
	out := map[string][]ipAt{}
	loc := ""
	for _, r := range rows {
		a, b, c := cell(r.Cells, 0), cell(r.Cells, 1), cell(r.Cells, 2)
		switch {
		case a == "" || strings.EqualFold(a, "location"):
			continue
		case func() bool { _, err := netip.ParseAddr(a); return err == nil }():
			continue
		case b == "" && c == "" && !isRoleLabel(a):
			loc = a
			continue
		}
		if loc == "" || !strings.HasPrefix(strings.ToLower(a), "internet") {
			continue
		}
		for _, m := range ipv4RE.FindAllString(b, -1) {
			if ip, err := netip.ParseAddr(m); err == nil && !ip.IsPrivate() {
				out[ip.String()] = append(out[ip.String()], ipAt{loc: loc, row: r.Num})
			}
		}
	}
	return out
}

// ParseNotes reads the operator's notes file: "location | what to check",
// one per line. The location is the start of its header in the sheet, or a
// name the sheet does not have yet (a missing site). A line it cannot read is
// returned as a problem.
func ParseNotes(text string) ([]Cleanup, []string) {
	var out []Cleanup
	var problems []string
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		loc, note, ok := strings.Cut(line, "|")
		loc, note = strings.TrimSpace(loc), strings.TrimSpace(note)
		if !ok || loc == "" || note == "" {
			problems = append(problems, fmt.Sprintf("line %d: expected 'location | what to check'", n+1))
			continue
		}
		out = append(out, Cleanup{Location: loc, Kind: CNote, Why: note})
	}
	return out, problems
}

// PlaceNotes gives each note the row of the location it names, when the
// sheet has one (the start of a header, as in netrules.txt); a note about a
// site the sheet lacks keeps no row.
func PlaceNotes(notes []Cleanup, subs []Subnet) []Cleanup {
	out := append([]Cleanup(nil), notes...)
	for i := range out {
		k := normKey(out[i].Location)
		for _, s := range subs {
			if strings.HasPrefix(normKey(s.Location), k) {
				out[i].Location, out[i].Row = s.Location, s.LocRow
				break
			}
		}
	}
	return out
}
