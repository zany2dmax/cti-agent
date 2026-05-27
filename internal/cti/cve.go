package cti

import (
	"regexp"
	"sort"
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
