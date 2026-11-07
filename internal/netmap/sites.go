package netmap

import (
	"fmt"
	"net/netip"
	"strings"
)

// Subnet is one network row from the spreadsheet.
type Subnet struct {
	// Location is the site header the row sits under, as written.
	Location string
	// Role is the row's label: corp, security, netman, guest, voice, setup...
	Role string
	// Raw is the network cell as written, for messages.
	Raw string
	// Prefix is the parsed network, valid only when Valid.
	Prefix netip.Prefix
	Valid  bool
	// Inactive is set for a location (or row) marked decommissioned, free or
	// open to use: not a network anyone expects to be scanned.
	Inactive bool
}

// roleSkip are row labels that are not internal networks.
func roleSkip(label string) bool {
	l := strings.ToLower(label)
	return strings.HasPrefix(l, "internet")
}

func inactiveText(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "decommission") || strings.Contains(l, "<<<free>>>") ||
		strings.Contains(l, "open to use")
}

func cell(row []string, i int) string {
	if i < len(row) {
		return strings.TrimSpace(row[i])
	}
	return ""
}

// parseNetwork reads a network cell: "10.4.30.0/24", "192.168.201.0 /24", a bare
// address with a dotted mask in the next cell, or garbage ("10.29.30").
func parseNetwork(raw, maskCell string) (netip.Prefix, bool) {
	s := strings.ReplaceAll(strings.TrimSpace(raw), " ", "")
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, false
	}
	if bits, ok := maskBits(strings.TrimSpace(maskCell)); ok {
		return netip.PrefixFrom(a, bits).Masked(), true
	}
	return netip.PrefixFrom(a, 32), true
}

// maskBits turns "255.255.255.0" into 24.
func maskBits(m string) (int, bool) {
	a, err := netip.ParseAddr(m)
	if err != nil || !a.Is4() {
		return 0, false
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bits := 0
	for v&0x80000000 != 0 {
		bits++
		v <<= 1
	}
	if v != 0 {
		return 0, false // not a contiguous mask
	}
	return bits, true
}

// ParseSites reads the Sites sheet's rows into subnets.
//
// The sheet is laid out for people: a header row per site (a name in the first
// cell and nothing beside it), then rows of "label, network, vlan", with device
// rows (an address in the first cell) and notes between them. This follows
// that layout and nothing cleverer; a row it cannot read as a network keeps
// Valid false so the caller can say so rather than drop it.
func ParseSites(rows [][]string) []Subnet {
	var out []Subnet
	loc := ""
	locInactive := false
	for _, row := range rows {
		a, b, c := cell(row, 0), cell(row, 1), cell(row, 2)
		if a == "" {
			continue // a note under the previous row
		}
		if strings.EqualFold(a, "location") {
			continue // the column header
		}
		if _, err := netip.ParseAddr(a); err == nil {
			continue // a device row: an address and its name
		}
		if b == "" && c == "" {
			loc, locInactive = a, inactiveText(a)
			continue
		}
		if loc == "" || roleSkip(a) {
			continue
		}
		p, ok := parseNetwork(b, c)
		out = append(out, Subnet{
			Location: loc, Role: a, Raw: b, Prefix: p, Valid: ok,
			Inactive: locInactive || inactiveText(a),
		})
	}
	return out
}

// Describe is how a subnet reads in a message.
func (s Subnet) Describe() string {
	if s.Valid {
		return fmt.Sprintf("%s (%s)", s.Prefix, s.Role)
	}
	return fmt.Sprintf("%q (%s, not a network)", s.Raw, s.Role)
}
