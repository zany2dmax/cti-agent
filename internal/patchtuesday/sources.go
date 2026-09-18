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
	Name    string
	URL     string
	Fetched bool
	Err     string // why it failed, for the DEGRADED banner
	Text    string // tags stripped, entities decoded
	RawHTML string
}

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
	reTag     = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpaces  = regexp.MustCompile(`[ \t]+`)
	reNewline = regexp.MustCompile(`\n{3,}`)
)

// StripHTML reduces a page to readable text. Deliberately crude: the numbers
// we want appear in prose, and a real HTML parser would be a dependency for
// no gain. Block-level tags become newlines so sentences do not run together.
func StripHTML(h string) string {
	for _, re := range reDropBlocks {
		h = re.ReplaceAllString(h, " ")
	}
	h = regexp.MustCompile(`(?i)</(p|div|tr|li|h[1-6]|table)>`).ReplaceAllString(h, "\n")
	h = regexp.MustCompile(`(?i)<br\s*/?>`).ReplaceAllString(h, "\n")
	h = reTag.ReplaceAllString(h, " ")
	for from, to := range map[string]string{
		"&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": `"`,
		"&#8217;": "'", "&#8216;": "'", "&#8220;": `"`, "&#8221;": `"`,
		"&#8211;": "-", "&#8212;": "-", "&rsquo;": "'", "&lsquo;": "'",
		"&ldquo;": `"`, "&rdquo;": `"`, "&ndash;": "-", "&mdash;": "-",
		"&#39;": "'", "&apos;": "'",
	} {
		h = strings.ReplaceAll(h, from, to)
	}
	h = reSpaces.ReplaceAllString(h, " ")
	var out []string
	for _, l := range strings.Split(h, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return reNewline.ReplaceAllString(strings.Join(out, "\n"), "\n\n")
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
	reCritical  = regexp.MustCompile(`(?i)([\d,]+)\s*</?b?>?\s*critical`)
	reImportant = regexp.MustCompile(`(?i)([\d,]+)\s*</?b?>?\s*important`)
	reEdge      = regexp.MustCompile(`(?i)addressed\s+([\d,]+)\s+vulnerabilit\w+\s+in\s+Microsoft\s+Edge`)

	reZeroDay = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(In this month'?s updates?,? Microsoft has (?:not )?addressed[^.]*zero-day[^.]*\.)`),
		regexp.MustCompile(`(?i)(Microsoft has (?:not )?addressed [^.]*zero-day[^.]*\.)`),
		regexp.MustCompile(`(?i)((?:two|three|four|five|six|one|no|\d+) (?:actively exploited )?zero-day[^.]*\.)`),
	}

	reProducts = regexp.MustCompile(
		`(?i)includes updates for vulnerabilities in ([^.]+?)(?:, and more)?\.`)
	reAdobe = regexp.MustCompile(
		`(?i)(Adobe has released [^.]*\.(?:[^.]*\.)?)`)

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

func firstString(text string, pats []*regexp.Regexp) string {
	for _, re := range pats {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return strings.Join(strings.Fields(m[1]), " ")
		}
	}
	return ""
}

// Parse pulls the synopsis fields out of the fetched sources.
//
// The Qualys post is the richer source - it carries the category table, the
// Adobe section and the QQL - so its values win where both publish one.
// BleepingComputer contributes the headline flaw count and the zero-day
// narrative, which is what the subject line needs.
func Parse(d *Digest) {
	var qualys, bleeping *Source
	for i := range d.Sources {
		switch {
		case strings.Contains(strings.ToLower(d.Sources[i].Name), "qualys"):
			qualys = &d.Sources[i]
		default:
			bleeping = &d.Sources[i]
		}
	}

	pick := func(get func(*Source) int, order ...*Source) int {
		for _, s := range order {
			if s == nil || !s.Fetched {
				continue
			}
			if v := get(s); v > 0 {
				return v
			}
		}
		return 0
	}

	d.Total = pick(func(s *Source) int { return firstNumber(s.Text, reTotal) }, qualys, bleeping)
	d.Critical = pick(func(s *Source) int { return firstNumber(s.Text, []*regexp.Regexp{reCritical}) }, qualys, bleeping)
	d.Important = pick(func(s *Source) int { return firstNumber(s.Text, []*regexp.Regexp{reImportant}) }, qualys, bleeping)
	d.EdgeFixes = pick(func(s *Source) int { return firstNumber(s.Text, []*regexp.Regexp{reEdge}) }, qualys, bleeping)

	for _, s := range []*Source{bleeping, qualys} { // zero-days: the news source says it better
		if s != nil && s.Fetched && d.ZeroDayText == "" {
			d.ZeroDayText = firstString(s.Text, reZeroDay)
		}
	}
	for _, s := range []*Source{qualys, bleeping} {
		if s == nil || !s.Fetched {
			continue
		}
		if len(d.Products) == 0 {
			if m := reProducts.FindStringSubmatch(s.Text); len(m) > 1 {
				for _, p := range strings.Split(m[1], ",") {
					p = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(p), "and "))
					if p != "" && !strings.EqualFold(p, "and more") {
						d.Products = append(d.Products, p)
					}
				}
			}
		}
		if d.AdobeText == "" {
			d.AdobeText = firstString(s.Text, []*regexp.Regexp{reAdobe})
		}
	}

	if qualys != nil && qualys.Fetched {
		d.Categories = parseCategoryTable(qualys.RawHTML)
		d.SourceQQL = extractQQL(qualys.RawHTML, qualys.Text)
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
