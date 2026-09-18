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
	// Attempted records whether the scanner was actually asked. The zero value
	// is false on purpose. When correlation failed - no credentials, no
	// network, an API error - the old zero-value Exposure reported "the Qualys
	// KnowledgeBase has no QID mapping for any CVE in this release", which is
	// a specific diagnosis of a system it had never opened. "We did not look"
	// and "we looked and found nothing mappable" are different facts, and a
	// struct that cannot tell them apart will always publish the wrong one.
	Attempted   bool
	Unavailable string // why not, when Attempted is false

	// MappedCVEs are Patch Tuesday CVEs the KnowledgeBase could resolve to at
	// least one QID. Unmapped ones are tracked separately: a CVE with no QID
	// is not absent, it is unmeasurable, and the two must not be added up.
	MappedCVEs   []string
	UnmappedCVEs []string

	// QIDs is every QID actually queried, from either route below.
	QIDs []int

	// PublishedQIDs are the QIDs Qualys listed in the review's own QQL, and
	// the second route to a number. The KnowledgeBase CVE-to-QID mapping lags
	// a release by a day or two; the blog's QQL does not, because a human at
	// Qualys wrote it for this release. Querying only the mapping meant the
	// report said "not yet measurable" in one paragraph and printed fifteen
	// perfectly good QIDs in the next.
	PublishedQIDs []int
	// PublishedOnlyQIDs have open detections but were reachable only from the
	// published list - no CVE in the release mapped to them. Real exposure the
	// CVE route alone would have missed entirely.
	PublishedOnlyQIDs []int

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

// Unmeasured is the Exposure to use when the scanner could not be reached. It
// carries the reason so the email can say what went wrong instead of inventing
// a finding about the KnowledgeBase.
func Unmeasured(reason string) Exposure {
	return Exposure{Attempted: false, Unavailable: reason}
}

// Measurable reports whether any QID was queried at all. Everything the email
// says about the estate has to be gated on this.
func (e Exposure) Measurable() bool { return e.Attempted && len(e.QIDs) > 0 }

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
// cveToQIDs maps each Patch Tuesday CVE to its QIDs; publishedQIDs are the
// ones Qualys listed in the review itself; detections maps QID to what the
// scanner found. Hosts are unioned rather than summed, because the same
// machine appears under many QIDs and adding them produces a host count larger
// than the estate. Detections are summed once per QID for the same reason in
// reverse: a QID reachable from two CVEs is one set of findings, not two.
func Summarise(cves []string, cveToQIDs map[string][]int, publishedQIDs []int,
	detections map[int]DetectionLike, kbStale bool) Exposure {

	e := Exposure{Attempted: true, KBStale: kbStale}
	hostSet := map[string]bool{}
	qidSet := map[int]bool{}
	presentSet := map[string]bool{}
	counted := map[int]bool{}
	fromCVE := map[int]bool{}

	// add queries one QID into the totals and reports whether it had anything.
	add := func(q int) bool {
		qidSet[q] = true
		d, ok := detections[q]
		if !ok || d.HostCount == 0 {
			return false
		}
		if !counted[q] {
			counted[q] = true
			e.Detections += d.HostCount
			for _, h := range d.Hosts {
				if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
					hostSet[h] = true
				}
			}
		}
		return true
	}

	for _, cve := range cves {
		qids := cveToQIDs[strings.ToUpper(cve)]
		if len(qids) == 0 {
			e.UnmappedCVEs = append(e.UnmappedCVEs, cve)
			continue
		}
		e.MappedCVEs = append(e.MappedCVEs, cve)
		for _, q := range qids {
			fromCVE[q] = true
			if add(q) {
				presentSet[cve] = true
			}
		}
	}

	// The vendor's own list, second so that CVE attribution wins where both
	// routes reach the same QID.
	for _, q := range publishedQIDs {
		e.PublishedQIDs = append(e.PublishedQIDs, q)
		if add(q) && !fromCVE[q] {
			e.PublishedOnlyQIDs = append(e.PublishedOnlyQIDs, q)
		}
	}
	sort.Ints(e.PublishedQIDs)
	sort.Ints(e.PublishedOnlyQIDs)

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
// Four states, not three. The one that was missing is the first: correlation
// having failed outright. Without it a run with no Qualys credentials printed
// "the Qualys KnowledgeBase has no QID mapping for any CVE in this release" -
// a confident diagnosis of a KnowledgeBase that was never contacted, sitting
// directly above a QQL listing the release's QIDs. A report that cannot
// distinguish "not attempted" from "attempted and clean" will state the
// reassuring one, which is the failure this whole system exists to avoid.
func (e Exposure) ExposureLine(org string) string {
	switch {
	case !e.Attempted:
		why := e.Unavailable
		if why == "" {
			why = "the scanner was not queried"
		}
		return fmt.Sprintf(
			"Exposure for %s was NOT MEASURED in this run: %s. Nothing below says "+
				"anything about what is or is not present here - this is a gap in "+
				"the report, not a clean result.", org, why)

	case len(e.QIDs) == 0:
		return fmt.Sprintf(
			"Exposure for %s is not yet measurable: neither the Qualys "+
				"KnowledgeBase nor this month's review yielded a single QID for this "+
				"release. That happens within a day or two of Patch Tuesday; it is "+
				"not a clean result.", org)

	case e.Detections == 0:
		return fmt.Sprintf(
			"Exposure for %s: no open detections across the %d QID(s) checked for "+
				"this release. Either the estate is not affected or no scan has run "+
				"since the release - check the last scan date before treating this "+
				"as good news.", org, len(e.QIDs))

	default:
		line := fmt.Sprintf(
			"The Exposure for %s is ~%d new vulnerabilities across %d hosts.",
			org, e.Detections, e.Hosts)
		// Worth saying out loud: these would have been invisible if the report
		// had only trusted the CVE-to-QID mapping.
		if n := len(e.PublishedOnlyQIDs); n > 0 {
			line += fmt.Sprintf(
				" %d of the detecting QID(s) came from the QID list Qualys "+
					"published in this month's review rather than from the "+
					"KnowledgeBase CVE mapping.", n)
		}
		return line
	}
}

// CoverageNote explains an unmapped-CVE count without overstating it. Returns
// empty when there is nothing honest to add.
func (e Exposure) CoverageNote() string {
	if !e.Attempted || len(e.UnmappedCVEs) == 0 {
		return ""
	}
	note := fmt.Sprintf(
		"%d of this release's CVEs have no Qualys QID mapping. That is not the "+
			"same as not being present - it means coverage could not be "+
			"established for them.", len(e.UnmappedCVEs))
	if len(e.PublishedQIDs) > 0 {
		note += fmt.Sprintf(
			" The %d QID(s) published in this month's review were queried "+
				"regardless, so some of these may still be covered by the figures "+
				"above.", len(e.PublishedQIDs))
	}
	if e.KBStale {
		note += " The KnowledgeBase cache is stale, so treat all of these as unverified."
	}
	return note
}
