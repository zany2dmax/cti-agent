package qualys

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// THE FIX, FROM THE KNOWLEDGEBASE
//
// A WAS finding carries its QID, title, severity, URL and parameter - and not
// one word about how to fix it. Qualys keeps that on the QID, in the same
// KnowledgeBase the VM lane reads: DIAGNOSIS (what was found and how),
// CONSEQUENCE (what an attacker gets) and SOLUTION (the fix). A ticket that
// says "Severity 5, SQL injection, /search?q=" sends a developer off to
// research; one that also carries the KnowledgeBase's own solution text is a
// ticket they can act on.
//
// Same host and credentials as the VM lane's KnowledgeBase download, one GET
// per chunk of QIDs, details=All. The text is HTML; it is reduced to plain
// text here and bounded, because it goes into Jira and email.

// kbChunk QIDs per request. Well under any URL-length limit.
const kbChunk = 100

// maxRemedyField bounds each field. The KnowledgeBase's own texts are a few
// paragraphs; anything far longer is pasted reference material that belongs
// behind the link to the finding, not in a ticket.
const maxRemedyField = 4000

// Remedies looks up the fix for each finding ID (a QID). IDs that are not
// numbers - a finding with no QID carries its uniqueId instead - are skipped.
// Implements appscan.RemedyFetcher.
func (a *API) Remedies(ctx context.Context, ids []string) (map[string]appscan.Remedy, error) {
	var qids []int
	seen := map[int]bool{}
	for _, id := range ids {
		n, err := strconv.Atoi(strings.TrimSpace(id))
		if err != nil || n <= 0 || seen[n] {
			continue
		}
		seen[n] = true
		qids = append(qids, n)
	}
	sort.Ints(qids)
	out := map[string]appscan.Remedy{}
	var errs []error
	for i := 0; i < len(qids); i += kbChunk {
		end := i + kbChunk
		if end > len(qids) {
			end = len(qids)
		}
		got, err := a.kbChunk(ctx, qids[i:end])
		if err != nil {
			// Keep going: one bad chunk costs its own QIDs' fixes, not every
			// later chunk's. A finding without a remedy says so on its ticket.
			errs = append(errs, fmt.Errorf("QIDs %d-%d: %w", qids[i], qids[end-1], err))
			continue
		}
		for k, v := range got {
			out[k] = v
		}
	}
	return out, errors.Join(errs...)
}

func (a *API) kbChunk(ctx context.Context, qids []int) (map[string]appscan.Remedy, error) {
	parts := make([]string, len(qids))
	for i, q := range qids {
		parts[i] = strconv.Itoa(q)
	}
	q := url.Values{}
	q.Set("action", "list")
	q.Set("details", "All")
	q.Set("ids", strings.Join(parts, ","))
	body, err := a.get(ctx, "/api/4.0/fo/knowledge_base/vuln/?"+q.Encode())
	if err != nil {
		return nil, err
	}
	return parseKBRemedies(body)
}

// kbVulnDetail is one VULN with the three texts. Element names as the
// KnowledgeBase API documents them; a rename parses to empty strings, which
// the ticket reports as "fix not available" rather than as a fix.
type kbVulnDetail struct {
	QID         int    `xml:"QID"`
	Diagnosis   string `xml:"DIAGNOSIS"`
	Consequence string `xml:"CONSEQUENCE"`
	Solution    string `xml:"SOLUTION"`
	CVEs        []struct {
		ID string `xml:"ID"`
	} `xml:"CVE_LIST>CVE"`
}

func parseKBRemedies(body []byte) (map[string]appscan.Remedy, error) {
	var doc struct {
		Vulns []kbVulnDetail `xml:"RESPONSE>VULN_LIST>VULN"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("qualys KnowledgeBase: response is not the expected XML: %w", err)
	}
	out := map[string]appscan.Remedy{}
	for _, v := range doc.Vulns {
		if v.QID == 0 {
			continue
		}
		r := appscan.Remedy{
			Diagnosis:   bound(htmlToText(v.Diagnosis)),
			Consequence: bound(htmlToText(v.Consequence)),
			Solution:    bound(htmlToText(v.Solution)),
		}
		for _, c := range v.CVEs {
			if id := strings.ToUpper(strings.TrimSpace(c.ID)); strings.HasPrefix(id, "CVE-") {
				r.CVEs = append(r.CVEs, id)
			}
		}
		if r.Diagnosis == "" && r.Consequence == "" && r.Solution == "" {
			continue
		}
		out[strconv.Itoa(v.QID)] = r
	}
	return out, nil
}

var (
	kbAnchorRE = regexp.MustCompile(`(?is)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
	kbBlockRE  = regexp.MustCompile(`(?i)<br\s*/?>|</?(p|div|tr|h[1-6]|ul|ol|table)[^>]*>`)
	kbItemRE   = regexp.MustCompile(`(?i)<li[^>]*>`)
	kbTagRE    = regexp.MustCompile(`(?s)<[^>]*>`)
	kbBlankRE  = regexp.MustCompile(`\n{3,}`)
	kbSpaceRE  = regexp.MustCompile(`[ \t\r\f\v]+`)
)

// htmlToText keeps paragraphs, list items and link targets, and nothing else.
// Links are kept as "text (url)" with http(s) targets only: the solution
// often IS the link to the vendor's patch, and a javascript: target has no
// business in a ticket.
func htmlToText(s string) string {
	s = kbAnchorRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := kbAnchorRE.FindStringSubmatch(m)
		href := html.UnescapeString(strings.TrimSpace(sub[1]))
		text := strings.TrimSpace(kbTagRE.ReplaceAllString(sub[2], ""))
		lower := strings.ToLower(href)
		if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
			return text
		}
		if text == "" || text == href {
			return href
		}
		return text + " (" + href + ")"
	})
	s = kbItemRE.ReplaceAllString(s, "\n- ")
	s = kbBlockRE.ReplaceAllString(s, "\n")
	s = kbTagRE.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(kbSpaceRE.ReplaceAllString(l, " "))
	}
	s = strings.Join(lines, "\n")
	s = kbBlankRE.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

func bound(s string) string {
	if len(s) <= maxRemedyField {
		return s
	}
	cut := s[:maxRemedyField]
	if i := strings.LastIndexAny(cut, ".\n"); i > maxRemedyField/2 {
		cut = cut[:i+1]
	}
	return strings.TrimSpace(cut) + " [...]"
}
