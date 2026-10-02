// Package triage extracts what code can find from a threat advisory, so that
// an analysis agent reading the same text has something to check itself
// against.
//
// # WHY THIS EXISTS
//
// The CVE lanes cannot see a whole class of threat. A September 2026 advisory
// described an active campaign against online retailers that compromised
// dozens of companies, stole 600,000 payment cards and destroyed two victims'
// databases - and contained ZERO CVEs. Not as an omission: the operator
// deliberately selected targets running bespoke code, and every flaw exploited
// was a one-off application defect that will never be assigned a CVE, never
// appear in a scanner feed, and never start an SLA clock.
//
// enrich.py finds no CVE in that mail, the digest never mentions it, and
// cti-mailbox correctly leaves it in the inbox as "not a CTI advisory this
// lane is responsible for". The intelligence arrives and dies there.
//
// # WHAT THIS PACKAGE IS AND IS NOT
//
// It is deterministic extraction only: regular expressions over text, no model
// call, no judgement. It answers "what identifiers are in this document",
// never "does this matter to us". Relevance is the agent's job, against
// ORG-PROFILE.md, and keeping the two apart is what makes this half testable
// and cheap enough to run on every message.
//
// Per the agent's standing instructions, this extraction is "a cross-check,
// not a limit": the agent may find indicators the regex missed and should say
// when the regex listed something that is not really an indicator. So this
// code is deliberately tuned to be PRECISE rather than exhaustive. A false
// positive costs the agent a correction; a false negative costs nothing,
// because the agent reads the same text.
package triage

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cveRE has no upper bound on the sequence digits.
//
// CVE ids are assigned per year starting from 1, so four digits is ordinary
// and six exists (CVE-2026-102331). An early version of the CVE regex in this
// repository used {4,7} and would have silently dropped them; the sequence is
// unbounded by specification, so this is.
var cveRE = regexp.MustCompile(`(?i)\bCVE-(\d{4})-(\d{4,})\b`)

// techniqueRE matches a MITRE ATT&CK technique, with or without a sub-id.
var techniqueRE = regexp.MustCompile(`\bT(\d{4})(\.\d{3})?\b`)

// abbreviatedSubRE catches the shorthand an analyst writes when listing
// sub-techniques of the same parent: "T1566.001/002" means T1566.001 AND
// T1566.002. Taking only the first loses half the mapping.
var abbreviatedSubRE = regexp.MustCompile(`\bT(\d{4})\.(\d{3})((?:/\d{3})+)\b`)

// ipRE matches a dotted quad. Octet VALUES are validated separately, because
// a regex that also range-checks is unreadable and this one is read often.
//
// The negative context either side is load-bearing. Advisories are full of
// version strings - python3.12, DeepSeek v4.1, opus-4.6 - and dates like
// 2026-09-22. Without the guards, "3.12.1.4" in a version table becomes an
// indicator and somebody blocks it.
var ipRE = regexp.MustCompile(`(^|[^\w.])(\d{1,3}(?:\.\d{1,3}){3})($|[^\w.])`)

// defangedRE matches an indicator a publisher has deliberately broken so it
// cannot be clicked: b8t[.]shop, 155.254.22[.]215, ti[@]gambit.security,
// hxxps://evil.example.
//
// ONLY DEFANGED HOSTNAMES ARE EXTRACTED, and that is a deliberate limit.
// Matching bare domains in prose produces far more noise than signal: every
// product name, file name and vendor reference in an advisory looks like a
// hostname to a regex, and "wp-config.php" or "cts.js" would arrive in the
// indicator list beside a real C2. Defanging is an explicit signal from the
// author that a string is hostile. The agent reads the same document and is
// asked to report indicators this missed.
//
// The repeat is LABEL(SEP LABEL)+, not (LABEL SEP LABEL)+. The second form
// looks equivalent and is not: it consumes "cdn[.]netlfjs" and then needs a
// bare label to start the next repetition, but the next character is the "["
// of the following separator - so it stops, and a three-label host is
// truncated to two. cdn[.]netlfjs[.]com arrived as cdn[.]netlfjs, which is
// not a hostname anybody can block.
var defangedRE = regexp.MustCompile(
	`(?i)\b` + dnsLabel + `(?:` + defangSep + dnsLabel + `)+\b`)

const (
	dnsLabel  = `[a-z0-9](?:[a-z0-9-]*[a-z0-9])?`
	defangSep = `(?:\s?(?:\[\.\]|\(\.\)|\[dot\])\s?|\.)`
)

// hasDefang reports whether a candidate contains an actual defang marker. The
// pattern above can match ordinary dotted text, so this is what separates
// "the author marked this hostile" from "this sentence has a full stop".
var hasDefang = regexp.MustCompile(`(?i)\[\.\]|\(\.\)|\[dot\]|\[@\]|\(@\)|\[at\]|hxxps?://`)

var defangedEmailRE = regexp.MustCompile(
	`(?i)\b[a-z0-9._%+-]+\s?(?:\[@\]|\(@\)|\[at\])\s?[a-z0-9.-]+\.[a-z]{2,}\b`)

// urlRE matches live links, including defanged schemes.
var urlRE = regexp.MustCompile(`(?i)\bh(?:tt|xx)ps?://[^\s<>"'\x60)\]]+`)

// Extraction is what code found, before anything read the text.
type Extraction struct {
	CVEs       []string
	Techniques []string
	Indicators []string
	Links      []string
}

// Empty reports whether nothing identifiable was found.
//
// Worth asking explicitly, because "no CVEs" is a FINDING for this lane, not a
// failure. The campaign this package was written for had none, and a caller
// that treats an empty CVE list as "nothing here" reproduces exactly the blind
// spot the lane exists to close.
func (e Extraction) Empty() bool {
	return len(e.CVEs) == 0 && len(e.Techniques) == 0 &&
		len(e.Indicators) == 0 && len(e.Links) == 0
}

// Extract runs every pattern over the text.
func Extract(body string) Extraction {
	return Extraction{
		CVEs:       extractCVEs(body),
		Techniques: extractTechniques(body),
		Indicators: extractIndicators(body),
		Links:      extractLinks(body),
	}
}

func extractCVEs(s string) []string {
	var out []string
	for _, m := range cveRE.FindAllStringSubmatch(s, -1) {
		out = append(out, "CVE-"+m[1]+"-"+m[2])
	}
	return uniqueSorted(out)
}

func extractTechniques(s string) []string {
	var out []string

	// Expand the abbreviated form first, then let the general pattern pick up
	// everything else. Both run over the whole text; duplicates are collapsed.
	for _, m := range abbreviatedSubRE.FindAllStringSubmatch(s, -1) {
		parent, first, rest := m[1], m[2], m[3]
		out = append(out, "T"+parent+"."+first)
		for _, sub := range strings.Split(strings.TrimPrefix(rest, "/"), "/") {
			if sub != "" {
				out = append(out, "T"+parent+"."+sub)
			}
		}
	}
	for _, m := range techniqueRE.FindAllStringSubmatch(s, -1) {
		out = append(out, "T"+m[1]+m[2])
	}

	// A bare parent is dropped when a sub-technique of it is also present:
	// "T1505.003" already says T1505, and listing both reads like two
	// findings. The reverse is not true - T1190 with no sub-technique stays.
	subParents := map[string]bool{}
	for _, t := range out {
		if i := strings.IndexByte(t, '.'); i > 0 {
			subParents[t[:i]] = true
		}
	}
	var kept []string
	for _, t := range out {
		if !strings.ContainsRune(t, '.') && subParents[t] {
			continue
		}
		kept = append(kept, t)
	}
	return uniqueSorted(kept)
}

func extractIndicators(s string) []string {
	var out []string

	for _, loc := range ipRE.FindAllStringSubmatchIndex(s, -1) {
		ip := s[loc[4]:loc[5]]
		if !validIPv4(ip) || looksLikeAVersion(s, loc[4]) {
			continue
		}
		out = append(out, ip)
	}
	for _, m := range defangedEmailRE.FindAllString(s, -1) {
		out = append(out, normaliseSpaces(m))
	}
	for _, m := range defangedRE.FindAllString(s, -1) {
		if !hasDefang.MatchString(m) {
			continue // ordinary dotted text, not a marked indicator
		}
		out = append(out, normaliseSpaces(m))
	}
	return uniqueSorted(out)
}

func extractLinks(s string) []string {
	var out []string
	for _, m := range urlRE.FindAllString(s, -1) {
		// Trailing punctuation belongs to the sentence, not the URL.
		out = append(out, strings.TrimRight(m, ".,;:"))
	}
	return uniqueSorted(out)
}

// validIPv4 range-checks the octets and rejects the leading-zero forms that
// are almost always a version string rather than an address.
func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// versionPrefixRE matches the words that precede a version number.
//
// A four-part version string is INDISTINGUISHABLE from an IPv4 address by
// shape: "3.12.1.4" is both. Shape alone cannot settle it, so this checks the
// words immediately before.
//
// It matters more than a tidy indicator list. 3.12.1.4 is real, routable AWS
// space - an operator pasting the extraction into a blocklist would drop
// somebody's production traffic because an advisory mentioned a library
// version. Worth being wrong in the quiet direction.
//
// A heuristic, and deliberately a small one. The agent reads the same text
// with the full sentence in front of it and is asked to report indicators the
// regex missed, so a false negative here is recoverable and a false positive
// is not.
// The leading \b is not optional. Without it "ver" matches inside "serVER",
// so "the server 172.245.89.137 hosts it" - the most ordinary sentence in any
// advisory - had its C2 address silently dropped. A guard against false
// positives that creates false negatives on the common case is worse than no
// guard at all.
var versionPrefixRE = regexp.MustCompile(`(?i)\b(?:version|ver\.?|v|release|build)\s*$`)

// looksLikeAVersion reports whether the text immediately before start reads
// as a version introduction.
func looksLikeAVersion(s string, start int) bool {
	from := start - 16
	if from < 0 {
		from = 0
	}
	return versionPrefixRE.MatchString(s[from:start])
}

// Refang turns a defanged indicator back into its real form.
//
// NOT used when building the agent's input - the indicator is passed through
// exactly as published, because refanging text that is about to be embedded in
// a prompt would hand a live hostname to something that reads attacker-written
// content. This exists for a later hunting lane that needs to query logs.
func Refang(s string) string {
	r := strings.NewReplacer(
		"[.]", ".", "(.)", ".", "[dot]", ".", "[DOT]", ".",
		"[@]", "@", "(@)", "@", "[at]", "@", "[AT]", "@",
		"hxxp://", "http://", "hxxps://", "https://",
		"hXXp://", "http://", "hXXps://", "https://",
	)
	return normaliseSpaces(r.Replace(s))
}

func normaliseSpaces(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Message is one advisory to be triaged.
type Message struct {
	ID       string
	Received time.Time
	Sender   string
	Subject  string
	Body     string
}

// Markers are the fences the agent is told to treat as the untrusted boundary.
const (
	BeginContent = "<<<BEGIN UNTRUSTED CONTENT"
	EndContent   = "END UNTRUSTED CONTENT>>>"
)

// stripMarkers removes any text that imitates the content fences.
//
// THE WHOLE TRUST BOUNDARY IS THESE TWO STRINGS. An advisory containing the
// literal end marker could close the untrusted region early and have the rest
// of its text read as if it came from us - which is the one injection this
// format is specifically shaped to prevent. Attacker-controlled text cannot be
// allowed to write the fence that contains it.
func stripMarkers(s string) string {
	return strings.NewReplacer(
		BeginContent, "[begin-marker removed]",
		EndContent, "[end-marker removed]",
	).Replace(s)
}

// RenderInput builds the file the triage agent reads.
//
// The shape is fixed by the agent's standing instructions: header block,
// deterministic extraction, then the body inside the fences. Changing it here
// without changing agents/triage/CLAUDE.md breaks the contract silently - the
// agent would still answer, just about the wrong thing.
func RenderInput(m Message, e Extraction) string {
	var b strings.Builder

	fmt.Fprintf(&b, "MESSAGE-ID: %s\n", oneLine(m.ID))
	fmt.Fprintf(&b, "RECEIVED:   %s\n", m.Received.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "SENDER:     %s\n", oneLine(m.Sender))
	fmt.Fprintf(&b, "SUBJECT:    %s\n\n", oneLine(m.Subject))

	b.WriteString("DETERMINISTIC EXTRACTION (found by code, before you read anything):\n")
	writeField(&b, "cves", e.CVEs)
	writeField(&b, "techniques", e.Techniques)
	writeField(&b, "indicators", e.Indicators)
	writeField(&b, "links", e.Links)

	b.WriteString("\n" + BeginContent + "\n")
	b.WriteString(stripMarkers(m.Body))
	if !strings.HasSuffix(m.Body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString(EndContent + "\n")
	return b.String()
}

// writeField prints one extraction line, and says "none" rather than leaving
// it blank. An empty line reads as "the extractor did not run"; "none" is a
// result, and for this lane it is frequently the important one.
func writeField(b *strings.Builder, name string, vals []string) {
	v := "none"
	if len(vals) > 0 {
		v = strings.Join(vals, ", ")
	}
	fmt.Fprintf(b, "  %-12s %s\n", name+":", v)
}

// oneLine keeps a header to one line. A newline in the header block would let
// a crafted subject inject a fake header - the same reasoning as collapsing
// whitespace in a mail subject.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ─── the organisation profile ───────────────────────────────────────────────

// ProfileSentinel marks a profile that has not been filled in.
//
// The installer copies the template to /etc/cti-agent/ORG-PROFILE.md so the
// operator has a file to edit rather than an install command to find. That
// convenience needs a safety net: an unfilled profile reads perfectly well to
// an agent, which then concludes "we do not appear to run anything like that"
// and returns a confident "unlikely" for a campaign aimed straight at the
// organisation.
//
// Placeholder CREDENTIALS fail loudly - they cannot authenticate, so the lane
// stops. Placeholder PROSE fails silently and confidently, which is worse. The
// sentinel is what makes the silent case detectable.
const ProfileSentinel = "PROFILE-STATUS: TEMPLATE"

// ProfileState is how usable the deployed profile is.
type ProfileState int

const (
	// ProfileMissing means no file. Relevance must be "unknown".
	ProfileMissing ProfileState = iota
	// ProfileTemplate means the file exists but is the unfilled template.
	// Treated exactly like missing - never as an empty description of a real
	// organisation.
	ProfileTemplate
	// ProfileFilled means somebody wrote it and removed the sentinel.
	ProfileFilled
)

func (p ProfileState) String() string {
	switch p {
	case ProfileFilled:
		return "filled"
	case ProfileTemplate:
		return "template (unfilled)"
	default:
		return "missing"
	}
}

// Usable reports whether the agent may reason about relevance at all.
func (p ProfileState) Usable() bool { return p == ProfileFilled }

// ClassifyProfile inspects profile text.
//
// Takes the CONTENT rather than a path, so the decision is testable without a
// filesystem and the caller decides how to handle a read error - which for
// this lane is the same as missing.
func ClassifyProfile(content string, readErr error) ProfileState {
	if readErr != nil {
		return ProfileMissing
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), ProfileSentinel) {
			return ProfileTemplate
		}
	}
	if strings.TrimSpace(content) == "" {
		return ProfileMissing
	}
	return ProfileFilled
}
