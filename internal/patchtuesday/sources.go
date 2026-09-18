package patchtuesday

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Source is one fetched wrap-up article.
type Source struct {
	Name string
	// Role says what this source IS, independently of what it is called.
	// Parse used to identify the Qualys blog by looking for "qualys" in the
	// name, and the exposure placeholder appended after a failed correlation is
	// called "Qualys Host Detection (exposure)" - it matches that test, has no
	// text, and would take the blog's place. Roles cannot collide by wording.
	Role    string
	URL     string
	Fetched bool
	Err     string // why it failed, for the DEGRADED banner
	Text    string // tags stripped, entities decoded
	RawHTML string
}

// Source roles.
const (
	RoleQualysBlog = "qualys-blog"
	RoleBleeping   = "bleepingcomputer"
	RoleExposure   = "qualys-host-detection"
)

// Digest is everything the lane extracted, before correlation.
type Digest struct {
	Year  int
	Month time.Month

	Sources []Source

	// Headline counts. Zero means "not found in the sources" - reported as
	// unknown rather than as zero, because a release with no vulnerabilities
	// has never happened and printing 0 would read as a parsing success.
	Total       int
	Critical    int
	Important   int
	EdgeFixes   int
	ZeroDayText string // the vendor's own sentence, quoted rather than counted

	Products   []string
	Categories []Category
	AdobeText  string

	CVEs []string

	// QQL lifted verbatim from the Qualys post when it publishes one. Never
	// paraphrased: a query someone will paste into a console has to be exactly
	// what the source said, or it silently returns the wrong set.
	SourceQQL []string

	// From records which source each figure came from. Added because the
	// August replay printed a total of 400 when the Qualys post says 421, and
	// there was no way to tell from the output which page had been believed.
	// A number that might be wrong should name its own source.
	From map[string]string
}

// PublishedQIDs are the QIDs Qualys itself lists in the review's QQL. These
// are the release's QIDs, curated by the vendor on the day, and they arrive
// before the KnowledgeBase CVE-to-QID mapping catches up - so they are the
// difference between measurable exposure on Patch Tuesday + 1 and a report
// that says "not yet measurable" while printing the QIDs in the next
// paragraph.
func (d *Digest) PublishedQIDs() []int {
	return QIDsFromQQL(d.SourceQQL)
}

// Category is one row of the Qualys "classified as follows" table.
type Category struct {
	Name       string
	Quantity   int
	Severities string
}

const userAgent = "cti-agent-patchtuesday/1.0 (+security team internal tooling)"

// QualysURL builds the canonical Qualys review URL. The date path is Patch
// Tuesday itself, which is computable - verified against the May 2026
// (2026/05/12) and September 2026 (2026/09/08) posts.
func QualysURL(year int, month time.Month) string {
	pt := PatchTuesday(year, month)
	return fmt.Sprintf(
		"https://blog.qualys.com/vulnerabilities-threat-research/%04d/%02d/%02d/"+
			"microsoft-patch-tuesday-%s-%d-security-update-review",
		pt.Year(), int(pt.Month()), pt.Day(),
		strings.ToLower(month.String()), year)
}

// BleepingURLCandidates returns plausible URLs. The slug embeds the flaw count
// and zero-day count ("...fixes-966-flaws-2-zero-days"), which cannot be known
// before reading the article - so the listing page is the reliable route and
// these are only a fast path.
func BleepingURLCandidates(year int, month time.Month) []string {
	m := strings.ToLower(month.String())
	base := fmt.Sprintf("https://www.bleepingcomputer.com/news/microsoft/microsoft-%s-%d-patch-tuesday", m, year)
	return []string{base + "/"}
}

// BleepingListing is where to look for the real URL.
const BleepingListing = "https://www.bleepingcomputer.com/tag/patch-tuesday/"

var reBleepingHref = regexp.MustCompile(
	`href="(https://www\.bleepingcomputer\.com/news/microsoft/microsoft-[a-z]+-\d{4}-patch-tuesday-[^"]*)"`)

// FindBleepingArticle picks this month's article out of a listing page.
//
// Needed because the slug carries the flaw and zero-day counts - the very
// numbers we are fetching the page to learn - so it cannot be constructed in
// advance. Matching on the month and year in the slug is stable across the
// parts that do vary.
func FindBleepingArticle(listingHTML string, year int, month time.Month) string {
	want := fmt.Sprintf("microsoft-%s-%d-patch-tuesday",
		strings.ToLower(month.String()), year)
	for _, m := range reBleepingHref.FindAllStringSubmatch(listingHTML, -1) {
		if strings.Contains(m[1], want) {
			return m[1]
		}
	}
	return ""
}

// Fetch retrieves one URL. A failure is returned in the Source rather than as
// an error: one unavailable wrap-up degrades the synopsis, it does not cancel
// the month.
func Fetch(ctx context.Context, client *http.Client, name, url string) Source {
	s := Source{Name: name, URL: url}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.Err = err.Error()
		return s
	}
	// Identify honestly. Some publishers rate-limit or block unrecognised
	// agents, and if that happens the right response is to say so in the
	// email, not to disguise the request.
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		s.Err = err.Error()
		return s
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		s.Err = "read failed: " + err.Error()
		return s
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		s.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return s
	}
	s.RawHTML = string(body)
	s.Text = StripHTML(s.RawHTML)
	s.Fetched = true
	return s
}

// Go's regexp is RE2: no backreferences, no lookaround. This started life as
// <(script|style|noscript)\b.*?</\1> - valid PCRE, and a PANIC at init in Go,
// so the whole package failed to load rather than failing a test. One pattern
// per tag instead.
var reDropBlocks = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`),
	regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style\s*>`),
	regexp.MustCompile(`(?is)<noscript\b[^>]*>.*?</noscript\s*>`),
	// A truncated page can leave an unclosed <script>; drop bare openers too.
	regexp.MustCompile(`(?is)<script\b[^>]*>`),
}

var (
	reTag      = regexp.MustCompile(`(?s)<[^>]+>`)
	reBlockEnd = regexp.MustCompile(`(?i)</(p|div|tr|li|h[1-6]|table|blockquote)>`)
	reBR       = regexp.MustCompile(`(?i)<br\s*/?>`)
	// Every kind of space, collapsed to one. U+00A0 and friends are included
	// deliberately: Go's \s is ASCII-only ([\t\n\f\r ]), so a literal
	// non-breaking space - which WordPress emits constantly, and which the
	// &nbsp; entity map never sees because it is already a character, not an
	// entity - does not match \s and silently breaks every "number followed by
	// a word" pattern in this file. Newlines are in here too; block boundaries
	// are preserved separately, see blockSep.
	reWS = regexp.MustCompile("[ \t\r\n\f\v\u00a0\u2007\u202f\u2009\u200a]+")
)

// blockSep marks a block boundary while whitespace is being normalised, so
// that after StripHTML each block is exactly ONE line.
//
// That invariant is what the prose patterns rely on when they bound a sentence
// with [^.\n]. Without it, a paragraph that merely WRAPPED in the page source
// is two lines here, and a bounded pattern cuts the sentence in half. Not
// hypothetical: the review's zero-day sentence wraps, and line-bounding
// without this reduced it from the vendor's full sentence to nothing at all -
// which the renderer would have shown by silently omitting the Zero-days
// section, with no error anywhere.
const blockSep = "\x00"

// punctuation maps the characters a CMS substitutes for ASCII. Entities are
// decoded elsewhere; these arrive as literal UTF-8 and are the reason
// `month'?s` failed to match the real page's "month’s".
var punctuation = map[string]string{
	"\u2019": "'", "\u2018": "'", "\u201c": `"`, "\u201d": `"`,
	"\u2013": "-", "\u2014": "-", "\u2026": "...", "\u2011": "-",
	"\u00a0": " ", "\u2007": " ", "\u202f": " ", "\u2009": " ", "\u200a": " ",
	"\u200b": "", "\ufeff": "",
}

// StripHTML reduces a page to readable text. Deliberately crude: the numbers
// we want appear in prose, and a real HTML parser would be a dependency for
// no gain. Block-level tags become newlines so sentences do not run together.
func StripHTML(h string) string {
	for _, re := range reDropBlocks {
		h = re.ReplaceAllString(h, " ")
	}
	h = reBlockEnd.ReplaceAllString(h, blockSep)
	h = reBR.ReplaceAllString(h, blockSep)
	h = reTag.ReplaceAllString(h, " ")
	for from, to := range map[string]string{
		"&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": `"`,
		"&#8217;": "'", "&#8216;": "'", "&#8220;": `"`, "&#8221;": `"`,
		"&#8211;": "-", "&#8212;": "-", "&rsquo;": "'", "&lsquo;": "'",
		"&ldquo;": `"`, "&rdquo;": `"`, "&ndash;": "-", "&mdash;": "-",
		"&#39;": "'", "&apos;": "'", "&#160;": " ", "&#8230;": "...",
	} {
		h = strings.ReplaceAll(h, from, to)
	}
	// Then the same characters in their literal form. Decoding entities is not
	// enough: the published page contains "month’s" as UTF-8, not as &rsquo;.
	for from, to := range punctuation {
		h = strings.ReplaceAll(h, from, to)
	}
	// Collapse all whitespace, newlines included, so a wrapped paragraph
	// becomes one line; then put the block boundaries back.
	h = reWS.ReplaceAllString(h, " ")
	var out []string
	for _, blk := range strings.Split(h, blockSep) {
		if t := strings.TrimSpace(blk); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

var (
	reCVE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

	// Counts. Several phrasings across months and publishers, so each pattern
	// is tried in turn and the first match wins. A number that cannot be found
	// stays zero and is reported as "not stated" rather than guessed.
	reTotal = []*regexp.Regexp{
		regexp.MustCompile(`(?i)addresses\s+([\d,]+)\s+vulnerabilit`),
		regexp.MustCompile(`(?i)fixe[sd]\s+([\d,]+)\s+(?:security\s+)?flaws?`),
		regexp.MustCompile(`(?i)patche[sd]\s+([\d,]+)\s+(?:security\s+)?(?:flaws?|vulnerabilit)`),
		regexp.MustCompile(`(?i)([\d,]+)\s+security\s+(?:flaws?|vulnerabilit\w+)\s+(?:were\s+)?fixed`),
		regexp.MustCompile(`(?i)release\s+addresses\s+([\d,]+)`),
	}
	// These used to be one pattern each, of the form
	//   ([\d,]+)\s*</?b?>?\s*critical
	// which was written against raw HTML and then applied to stripped text. The
	// `<` in it is NOT optional, so against text it could never match, and both
	// figures silently read "not stated" in every email. Anchoring on the
	// publisher's actual wording is both correct and narrower: a bare
	// "N critical" would otherwise match the category table's "Critical: 3".
	reCritical = []*regexp.Regexp{
		regexp.MustCompile(`(?i)including\s+([\d,]+)\s+critical\b`),
		regexp.MustCompile(`(?i)([\d,]+)\s+critical[\s-]severity`),
	}
	reImportant = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\band\s+([\d,]+)\s+important\b`),
		regexp.MustCompile(`(?i)([\d,]+)\s+important[\s-]severity`),
	}
	reEdge = regexp.MustCompile(`(?i)addressed\s+([\d,]+)\s+vulnerabilit\w+\s+in\s+Microsoft\s+Edge`)

	// Prose patterns are bounded to a single line. StripHTML turns block
	// boundaries into newlines, so [^.\n] keeps a sentence match inside the
	// paragraph it started in. With plain [^.] the last of these ran off the
	// end of BleepingComputer's headline and through the site navigation until
	// it found a full stop, and the email published
	// "3 zero-days News Featured Latest OpenAI details more cases of..." as the
	// zero-day summary.
	reZeroDay = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(In this month'?s updates?,?\s+Microsoft has (?:not )?addressed[^.\n]*zero-day[^.\n]*\.)`),
		regexp.MustCompile(`(?i)(Microsoft has (?:not )?addressed[^.\n]*zero-day[^.\n]*\.)`),
		regexp.MustCompile(`(?i)(includ\w+[^.\n]*\bzero-day[^.\n]*\.)`),
		regexp.MustCompile(`(?i)((?:two|three|four|five|six|seven|one|no|\d+)\s+(?:actively exploited\s+)?zero-days?[^.\n]*\.)`),
	}

	// A product list is full of dots - "Windows HTTP.sys", ".NET", "ASP.NET" -
	// so it cannot be terminated with [^.]+. The published sentence ends with
	// ", and more.", which is a reliable anchor; failing that, a sentence ends
	// at a period followed by whitespace, which ".sys" is not.
	reProducts = []*regexp.Regexp{
		regexp.MustCompile(`(?i)includes updates for vulnerabilities in ([^\n]+?),?\s+and more\.`),
		regexp.MustCompile(`(?im)includes updates for vulnerabilities in ([^\n]+?)\.(?:\s|$)`),
	}
	reAdobe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(Adobe has released[^.\n]*\.(?:[^.\n]*\.)?)`),
	}

	// QQL. The Qualys posts publish a query as prose or in a code block; both
	// forms start with the same field path.
	reQQL = []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*(vulnerabilities\.vulnerability\s*:.*)$`),
		regexp.MustCompile(`(vulnerabilities\.vulnerability\s*:\s*\([^)]*\))`),
		regexp.MustCompile(`(vulnerabilities\.vulnerability\.[A-Za-z.]+\s*:\s*\[[^\]]*\])`),
	}
)

func firstNumber(text string, pats []*regexp.Regexp) int {
	for _, re := range pats {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			if n, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", "")); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

// maxProse caps a captured sentence. A runaway pattern produces a plausible
// paragraph of someone else's website rather than an obvious error, and the
// only reliable tell is that it is far too long to be the sentence asked for.
const maxProse = 400

func firstString(text string, pats []*regexp.Regexp) string {
	for _, re := range pats {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			s := strings.Join(strings.Fields(m[1]), " ")
			if s != "" && len(s) <= maxProse {
				return s
			}
		}
	}
	return ""
}

// The digit floor is 1, not 3. Patch Tuesday QIDs are all five or six digits,
// so a minimum of three looked harmlessly defensive - but Qualys does issue
// low QIDs (qid: 6 is DNS hostname), and a floor would have dropped one from a
// published query with no error anywhere. The literal "qid:" prefix is the
// context that makes a short number trustworthy; a bare number needs a length
// guard, a labelled one does not. The upper bound stays as a sanity limit.
var reQIDInQQL = regexp.MustCompile(`(?i)\bqid\s*:\s*(\d{1,9})`)

// QIDsFromQQL pulls the QID list out of a published QQL string, deduped and
// sorted. Parsing our own output format back in is deliberate: the QQL is the
// vendor's machine-readable statement of which detections this release
// introduced, and it is the only such statement available on day one.
func QIDsFromQQL(qqls []string) []int {
	seen := map[int]bool{}
	var out []int
	for _, q := range qqls {
		for _, m := range reQIDInQQL.FindAllStringSubmatch(q, -1) {
			n, err := strconv.Atoi(m[1])
			if err != nil || n <= 0 || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// Parse pulls the synopsis fields out of the fetched sources.
//
// The Qualys post is the richer source - it carries the category table, the
// Adobe section and the QQL - so its values win where both publish one.
// BleepingComputer contributes the headline flaw count and the zero-day
// narrative, which is what the subject line needs.
func Parse(d *Digest) {
	qualys, bleeping := roles(d.Sources)
	d.From = map[string]string{}

	// name records provenance alongside the value. Every figure in the email
	// can then be traced to the page that supplied it.
	pick := func(field string, get func(*Source) int, order ...*Source) int {
		for _, s := range order {
			if s == nil || !s.Fetched {
				continue
			}
			if v := get(s); v > 0 {
				d.From[field] = s.Name
				return v
			}
		}
		d.From[field] = "not found in any source"
		return 0
	}
	pickText := func(field string, pats []*regexp.Regexp, order ...*Source) string {
		for _, s := range order {
			if s == nil || !s.Fetched {
				continue
			}
			if v := firstString(s.Text, pats); v != "" {
				d.From[field] = s.Name
				return v
			}
		}
		d.From[field] = "not found in any source"
		return ""
	}

	d.Total = pick("total", func(s *Source) int { return firstNumber(s.Text, reTotal) }, qualys, bleeping)
	d.Critical = pick("critical", func(s *Source) int { return firstNumber(s.Text, reCritical) }, qualys, bleeping)
	d.Important = pick("important", func(s *Source) int { return firstNumber(s.Text, reImportant) }, qualys, bleeping)
	d.EdgeFixes = pick("edge", func(s *Source) int { return firstNumber(s.Text, []*regexp.Regexp{reEdge}) }, qualys, bleeping)

	// Zero-days from the Qualys post first. The news headline reads better in
	// isolation, but it is a headline: it has no sentence end of its own, which
	// is how site navigation ended up quoted in the August replay. The blog
	// writes a full sentence, and a full sentence is what gets quoted.
	d.ZeroDayText = pickText("zero_days", reZeroDay, qualys, bleeping)
	d.AdobeText = pickText("adobe", reAdobe, qualys, bleeping)

	for _, s := range []*Source{qualys, bleeping} {
		if s == nil || !s.Fetched || len(d.Products) > 0 {
			continue
		}
		for _, re := range reProducts {
			m := re.FindStringSubmatch(s.Text)
			if len(m) < 2 || len(m[1]) > maxProse {
				continue
			}
			for _, p := range strings.Split(m[1], ",") {
				p = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(p), "and "))
				if p != "" && !strings.EqualFold(p, "and more") {
					d.Products = append(d.Products, p)
				}
			}
			if len(d.Products) > 0 {
				d.From["products"] = s.Name
				break
			}
		}
	}

	if qualys != nil && qualys.Fetched {
		d.Categories = parseCategoryTable(qualys.RawHTML)
		d.SourceQQL = extractQQL(qualys.RawHTML, qualys.Text)
		d.From["qql"] = qualys.Name
	}

	// CVEs from every source that loaded, deduped and sorted.
	seen := map[string]bool{}
	for _, s := range d.Sources {
		if !s.Fetched {
			continue
		}
		for _, c := range reCVE.FindAllString(s.Text, -1) {
			seen[strings.ToUpper(c)] = true
		}
	}
	for c := range seen {
		d.CVEs = append(d.CVEs, c)
	}
	sort.Strings(d.CVEs)
}

// roles finds the two article sources. Role wins; the name heuristic is only a
// fallback for hand-built Digests, and it excludes anything calling itself a
// detection source so the exposure placeholder can never be read as the blog.
func roles(sources []Source) (qualys, bleeping *Source) {
	for i := range sources {
		s := &sources[i]
		switch s.Role {
		case RoleQualysBlog:
			qualys = s
			continue
		case RoleBleeping:
			bleeping = s
			continue
		case RoleExposure:
			continue
		}
		name := strings.ToLower(s.Name)
		switch {
		case strings.Contains(name, "detection") || strings.Contains(name, "exposure"):
			// Not an article.
		case strings.Contains(name, "qualys"):
			if qualys == nil {
				qualys = s
			}
		default:
			if bleeping == nil {
				bleeping = s
			}
		}
	}
	return qualys, bleeping
}

func extractQQL(raw, text string) []string {
	out, seen := []string{}, map[string]bool{}
	for _, src := range []string{raw, text} {
		for _, re := range reQQL {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				q := strings.TrimSpace(StripHTML(m[1]))
				q = strings.Join(strings.Fields(q), " ")
				if q != "" && !seen[q] && len(q) < 4000 {
					seen[q] = true
					out = append(out, q)
				}
			}
		}
	}
	return out
}

var (
	reRow  = regexp.MustCompile(`(?is)<tr\b[^>]*>(.*?)</tr>`)
	reCell = regexp.MustCompile(`(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>`)
)

// parseCategoryTable reads the "classified as follows" table: category,
// quantity, severity split. Parsed from the raw HTML because the shape is the
// information - stripped to text it becomes an unlabelled column of numbers.
func parseCategoryTable(raw string) []Category {
	var out []Category
	for _, row := range reRow.FindAllStringSubmatch(raw, -1) {
		cells := reCell.FindAllStringSubmatch(row[1], -1)
		if len(cells) < 3 {
			continue
		}
		name := strings.TrimSpace(StripHTML(cells[0][1]))
		qty := strings.TrimSpace(StripHTML(cells[1][1]))
		sev := strings.Join(strings.Fields(StripHTML(cells[2][1])), " ")
		n, err := strconv.Atoi(strings.ReplaceAll(qty, ",", ""))
		if err != nil || name == "" {
			continue // header row, or a table that is not this one
		}
		if !strings.Contains(strings.ToLower(name), "vulnerabilit") {
			continue // some posts carry unrelated tables
		}
		out = append(out, Category{Name: name, Quantity: n, Severities: sev})
	}
	return out
}

// Degraded lists the sources that did not load, for the banner.
func (d *Digest) Degraded() []string {
	var out []string
	for _, s := range d.Sources {
		if !s.Fetched {
			out = append(out, fmt.Sprintf("%s (%s)", s.Name, s.Err))
		}
	}
	return out
}
