package netmap

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

var cidrRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)

// headerBlocks are the networks a location's header names for itself, such as
// the /16 in "ARD Miami - FL - 10.4.0.0/16". A corp network outside all of them
// is usually a typo in the sheet.
func headerBlocks(header string) []netip.Prefix {
	var out []netip.Prefix
	for _, m := range cidrRE.FindAllString(header, -1) {
		if p, err := netip.ParsePrefix(m); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}

func within(blocks []netip.Prefix, p netip.Prefix) bool {
	for _, b := range blocks {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Rules are the operator's answers about locations the spreadsheet does not
// make clear. They are read from a root-owned file the operator edits, never
// guessed by the lane:
//
//	# location (the start of its header in the sheet) | what to do
//	HQ - Example Site - GA | use inside,corp
//	Datacenter - Example - GA | use Servers,VMs
//	Azure - 172.16.0.0/16 | ignore
//
// "use" names the row labels that count as the corp networks for that location
// (default: corp). "ignore" leaves the location out of the check.
type Rules struct {
	use    map[string][]string
	ignore map[string]bool
	keys   []string
}

func normKey(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// ParseRules reads the file's text. A line it cannot read is returned as a
// problem, not dropped silently.
func ParseRules(text string) (Rules, []string) {
	r := Rules{use: map[string][]string{}, ignore: map[string]bool{}}
	var problems []string
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		loc, act, ok := strings.Cut(line, "|")
		key := normKey(loc)
		act = strings.TrimSpace(act)
		if !ok || key == "" {
			problems = append(problems, fmt.Sprintf("line %d: expected 'location | use ROLES' or 'location | ignore'", n+1))
			continue
		}
		switch {
		case strings.EqualFold(act, "ignore"):
			r.ignore[key] = true
		case strings.HasPrefix(strings.ToLower(act), "use "):
			var roles []string
			for _, x := range strings.Split(act[4:], ",") {
				if x = strings.TrimSpace(x); x != "" {
					roles = append(roles, strings.ToLower(x))
				}
			}
			if len(roles) == 0 {
				problems = append(problems, fmt.Sprintf("line %d: 'use' needs at least one row label", n+1))
				continue
			}
			r.use[key] = roles
		default:
			problems = append(problems, fmt.Sprintf("line %d: %q is not 'use ROLES' or 'ignore'", n+1, act))
			continue
		}
		r.keys = append(r.keys, key)
	}
	// Longest key first, so "HQ - Example - GA" wins over "HQ".
	sort.SliceStable(r.keys, func(i, j int) bool { return len(r.keys[i]) > len(r.keys[j]) })
	return r, problems
}

// find returns the rule key for a location header, "" if none: the key is a
// prefix of the header, so the CIDR at the end of a header can change without
// breaking the rule.
func (r Rules) find(location string) string {
	l := normKey(location)
	for _, k := range r.keys {
		if strings.HasPrefix(l, k) {
			return k
		}
	}
	return ""
}

// Question is something the operator has to decide before the lane will act on
// a location.
type Question struct {
	Location string
	Why      string
	// Kind says what sort of problem it is, so a report can say who fixes it.
	Kind QuestionKind
	// Row is the spreadsheet row to look at (the corp row, or the location's
	// header when no row qualifies); zero when unknown.
	Row int
}

// QuestionKind classifies a Question.
type QuestionKind string

const (
	// QNoCorpRow: no row clearly counts as the location's corp network.
	QNoCorpRow QuestionKind = "no-corp-row"
	// QBlank: a corp row with no network written in it.
	QBlank QuestionKind = "blank-network"
	// QInvalid: a corp network that is not a valid CIDR.
	QInvalid QuestionKind = "invalid-network"
	// QOutside: a corp network outside the location's own block.
	QOutside QuestionKind = "outside-block"
	// QOverlap: a corp network that overlaps another location's.
	QOverlap QuestionKind = "overlap"
)

// Corp is a location's corporate network as the sheet gives it.
type Corp struct {
	Location string
	Subnet   Subnet
}

// SelectCorp picks, per active location, the networks that count as its
// corporate network (rows labelled corp, or whatever a rule says), and the
// questions for every location where that is not clear: no corp row, a corp
// network that is not a valid CIDR, or one that overlaps another location's.
//
// It never guesses. A location with no clear answer becomes a Question and is
// left out of the corp list, so nothing downstream acts on it.
func SelectCorp(subs []Subnet, rules Rules) ([]Corp, []Question) {
	var order []string
	byLoc := map[string][]Subnet{}
	for _, s := range subs {
		if _, ok := byLoc[s.Location]; !ok {
			order = append(order, s.Location)
		}
		byLoc[s.Location] = append(byLoc[s.Location], s)
	}
	var corp []Corp
	var qs []Question
	for _, loc := range order {
		rows := byLoc[loc]
		active := false
		for _, s := range rows {
			if !s.Inactive {
				active = true
			}
		}
		if !active {
			continue
		}
		key := rules.find(loc)
		if key != "" && rules.ignore[key] {
			continue
		}
		roles := []string{"corp"}
		if key != "" && len(rules.use[key]) > 0 {
			roles = rules.use[key]
		}
		var picked []Subnet
		var seenRoles []string
		bad, blank := "", false
		badRow, headRow := 0, 0
		for _, s := range rows {
			if headRow == 0 {
				headRow = s.LocRow
			}
			seenRoles = append(seenRoles, s.Role)
			if s.Inactive || !hasRole(roles, s.Role) {
				continue
			}
			if !s.Valid {
				if strings.TrimSpace(s.Raw) == "" {
					blank = true
				} else {
					bad = s.Raw
				}
				badRow = s.Row
				continue
			}
			picked = append(picked, s)
		}
		// A corp network outside the location's own block is probably a typo in
		// the sheet. An operator rule for the location says it is meant, so it
		// is not asked about again.
		if blocks := headerBlocks(loc); key == "" && len(picked) > 0 && len(blocks) > 0 {
			for _, s := range picked {
				if !within(blocks, s.Prefix) {
					bad = ""
					qs = append(qs, Question{Location: loc, Kind: QOutside, Row: s.Row,
						Why: fmt.Sprintf("its corp network %s is outside the location's own block (%s); "+
							"either the sheet has a typo or say so with a rule", s.Prefix, headerBlockList(blocks))})
					picked = nil
					break
				}
			}
			if picked == nil {
				continue
			}
		}
		switch {
		case blank && len(picked) == 0 && bad == "":
			qs = append(qs, Question{Location: loc, Kind: QBlank, Row: badRow, Why: "its corp row has no network written in it"})
		case bad != "":
			qs = append(qs, Question{Location: loc, Kind: QInvalid, Row: badRow,
				Why: fmt.Sprintf("its corp network %q is not a valid network", bad)})
		case len(picked) == 0:
			qs = append(qs, Question{Location: loc, Kind: QNoCorpRow, Row: headRow,
				Why: fmt.Sprintf("no row counts as its corp network (rows: %s); say which with a rule",
					strings.Join(dedupe(seenRoles), ", "))})
		default:
			for _, s := range picked {
				corp = append(corp, Corp{Location: loc, Subnet: s})
			}
		}
	}
	// Overlaps between different locations are a spreadsheet mistake until a
	// person says otherwise.
	drop := map[string]bool{}
	for i := range corp {
		for j := i + 1; j < len(corp); j++ {
			if corp[i].Location != corp[j].Location && overlaps(corp[i].Subnet.Prefix, corp[j].Subnet.Prefix) {
				for _, k := range []int{i, j} {
					if !drop[corp[k].Location] {
						drop[corp[k].Location] = true
						other := corp[j].Location
						if k == j {
							other = corp[i].Location
						}
						qs = append(qs, Question{Location: corp[k].Location, Kind: QOverlap, Row: corp[k].Subnet.Row,
							Why: fmt.Sprintf("its corp network %s overlaps %s's", corp[k].Subnet.Prefix, other)})
					}
				}
			}
		}
	}
	if len(drop) > 0 {
		kept := corp[:0]
		for _, c := range corp {
			if !drop[c.Location] {
				kept = append(kept, c)
			}
		}
		corp = kept
	}
	return corp, qs
}

func headerBlockList(blocks []netip.Prefix) string {
	var s []string
	for _, b := range blocks {
		s = append(s, b.String())
	}
	return strings.Join(s, ", ")
}

func hasRole(roles []string, role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if k := strings.ToLower(s); !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func overlaps(a, b netip.Prefix) bool { return a.Overlaps(b) }
