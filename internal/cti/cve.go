package cti

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var cveRe = regexp.MustCompile(`\bCVE-\d{4}-\d{4,7}\b`)

func ExtractCVEs(text string) []string {
	matches := cveRe.FindAllString(strings.ToUpper(text), -1)
	seen := map[string]bool{}
	for _, cve := range matches {
		seen[cve] = true
	}
	out := make([]string, 0, len(seen))
	for cve := range seen {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

// CVELess orders CVE IDs the way a human reads them: by year, then by
// sequence number.
//
// Plain string comparison puts CVE-2026-9586 after CVE-2026-83549, because
// "9" > "8" character-wise. CVE sequence numbers are variable length, so
// lexicographic order interleaves them meaninglessly and the report looks
// like it lost track of its own sorting.
func CVELess(a, b string) bool {
	ay, an, aok := splitCVE(a)
	by, bn, bok := splitCVE(b)
	// Anything unparseable falls back to string order and sorts last, so a
	// malformed ID is visible rather than silently reordering everything.
	if !aok || !bok {
		if aok != bok {
			return aok
		}
		return a < b
	}
	if ay != by {
		return ay < by
	}
	if an != bn {
		return an < bn
	}
	return a < b
}

// splitCVE pulls the year and sequence number out of a CVE ID.
func splitCVE(s string) (year, num int, ok bool) {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(s)), "-")
	if len(parts) != 3 || parts[0] != "CVE" {
		return 0, 0, false
	}
	y, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, false
	}
	return y, n, true
}
