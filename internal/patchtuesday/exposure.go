package patchtuesday

import (
	"fmt"
	"sort"
	"strings"
)

// Exposure is what this release actually landed on, according to the scanner.
//
// This is the number the audience cares about and the one no public wrap-up
// can provide: "966 flaws fixed" is a Microsoft fact, "~1510 new detections
// across 777 hosts" is a fact about us. Everything here comes from Host
// Detection, never from the articles.
type Exposure struct {
	// MappedCVEs are Patch Tuesday CVEs the KnowledgeBase could resolve to at
	// least one QID. Unmapped ones are tracked separately: a CVE with no QID
	// is not absent, it is unmeasurable, and the two must not be added up.
	MappedCVEs   []string
	UnmappedCVEs []string

	QIDs []int

	// Detections is the total count of open detections across all hosts; Hosts
	// is the distinct machine count. Both matter and neither substitutes: 1510
	// detections on 777 hosts is a very different picture from 1510 on three.
	Detections int
	Hosts      int

	// PresentCVEs are those with at least one detection somewhere. These are
	// the ones to highlight.
	PresentCVEs []string

	// KBStale is set when the CVE-to-QID cache could not be refreshed, which
	// makes every unmapped CVE "coverage unverified" rather than "not present".
	KBStale bool
}

// DetectionLike is the shape the Qualys client returns per QID. Declared here
// rather than importing the client so this package stays testable without a
// scanner and without a cyclic dependency.
type DetectionLike struct {
	QID       int
	HostCount int
	Hosts     []string
}

// Summarise folds per-QID detections into the numbers the email prints.
//
// cveToQIDs maps each Patch Tuesday CVE to its QIDs; detections maps QID to
// what the scanner found. Hosts are unioned rather than summed, because the
// same machine appears under many QIDs and adding them produces a host count
// larger than the estate.
func Summarise(cves []string, cveToQIDs map[string][]int,
	detections map[int]DetectionLike, kbStale bool) Exposure {

	e := Exposure{KBStale: kbStale}
	hostSet := map[string]bool{}
	qidSet := map[int]bool{}
	presentSet := map[string]bool{}

	for _, cve := range cves {
		qids := cveToQIDs[strings.ToUpper(cve)]
		if len(qids) == 0 {
			e.UnmappedCVEs = append(e.UnmappedCVEs, cve)
			continue
		}
		e.MappedCVEs = append(e.MappedCVEs, cve)
		for _, q := range qids {
			qidSet[q] = true
			d, ok := detections[q]
			if !ok || d.HostCount == 0 {
				continue
			}
			presentSet[cve] = true
			e.Detections += d.HostCount
			for _, h := range d.Hosts {
				if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
					hostSet[h] = true
				}
			}
		}
	}

	for q := range qidSet {
		e.QIDs = append(e.QIDs, q)
	}
	sort.Ints(e.QIDs)
	for c := range presentSet {
		e.PresentCVEs = append(e.PresentCVEs, c)
	}
	sort.Strings(e.PresentCVEs)
	sort.Strings(e.MappedCVEs)
	sort.Strings(e.UnmappedCVEs)
	e.Hosts = len(hostSet)
	return e
}

// DetectedQIDs are the QIDs with at least one open detection. The QQL is built
// from these rather than from every mapped QID, so pasting it into Qualys
// returns the vulnerabilities that are actually there - a query listing QIDs
// with no detections returns an empty set and looks broken.
func (e Exposure) DetectedQIDs(detections map[int]DetectionLike) []int {
	var out []int
	for _, q := range e.QIDs {
		if d, ok := detections[q]; ok && d.HostCount > 0 {
			out = append(out, q)
		}
	}
	sort.Ints(out)
	return out
}

// QQLForQIDs renders the query in the form the team already uses:
//
//	vulnerabilities.vulnerability: ( qid: 110525 or qid: 110526 or ... )
//
// Kept byte-identical in shape to what has been sent by hand for months.
// Someone pasting this into the Qualys console should not have to notice that
// a machine wrote it.
func QQLForQIDs(qids []int) string {
	if len(qids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(qids))
	for _, q := range qids {
		parts = append(parts, fmt.Sprintf("qid: %d", q))
	}
	return "vulnerabilities.vulnerability: ( " + strings.Join(parts, " or ") + " )"
}

// QQLForCVEs is the fallback when the KnowledgeBase has no QID mapping yet,
// which happens in the first day or two after a release. Qualys accepts a CVE
// filter, so the team still gets a usable query on the morning it matters.
func QQLForCVEs(cves []string) string {
	if len(cves) == 0 {
		return ""
	}
	return "vulnerabilities.vulnerability.cveIds: [ " + strings.Join(cves, ", ") + " ]"
}

// ExposureLine is the sentence the existing email leads with.
//
// Reads "unmeasured" rather than "0" when nothing could be mapped: on the
// morning after a release the KnowledgeBase often has not caught up, and
// printing "0 new vulnerabilities" would announce a clean estate on the
// strength of missing data.
func (e Exposure) ExposureLine(org string) string {
	switch {
	case len(e.MappedCVEs) == 0:
		return fmt.Sprintf(
			"Exposure for %s is not yet measurable - the Qualys KnowledgeBase has "+
				"no QID mapping for any CVE in this release yet. That is normal "+
				"within a day or two of Patch Tuesday; it is not a clean result.", org)
	case e.Detections == 0:
		return fmt.Sprintf(
			"Exposure for %s: no open detections yet across %d mapped CVE(s). "+
				"Either the estate is not affected or the scan has not run since "+
				"the release - check the last scan date before treating this as good news.",
			org, len(e.MappedCVEs))
	default:
		return fmt.Sprintf(
			"The Exposure for %s is ~%d new vulnerabilities across %d hosts.",
			org, e.Detections, e.Hosts)
	}
}
