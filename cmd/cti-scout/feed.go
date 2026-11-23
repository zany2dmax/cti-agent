package main

// Reading a feed as the Python lane did with xml.etree: RSS 2.0, RSS 1.0
// (RDF) and Atom, any namespace, every <item> or <entry> at any depth.

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode"
)

// node is an ElementTree element: text before its first child, and each
// child's tail after it. Comments and processing instructions are dropped,
// as ET.fromstring drops them.
type node struct {
	local    string
	attrs    []xml.Attr
	text     string
	tail     string
	children []*node
}

func (n *node) itertext(b *strings.Builder) {
	b.WriteString(n.text)
	for _, c := range n.children {
		c.itertext(b)
		b.WriteString(c.tail)
	}
}

// href is el.get("href"): the attribute with no namespace.
func (n *node) href() string {
	for _, a := range n.attrs {
		if a.Name.Space == "" && a.Name.Local == "href" {
			return a.Value
		}
	}
	return ""
}

func (n *node) iter(f func(*node)) {
	f(n)
	for _, c := range n.children {
		c.iter(f)
	}
}

func xmlSpace(s string) bool {
	return strings.Trim(s, " \t\r\n") == ""
}

// parseXML is ET.fromstring: one root element, nothing but whitespace,
// comments and processing instructions outside it.
func parseXML(raw []byte) (*node, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.CharsetReader = charsetReader
	var root *node
	var stack []*node
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if root != nil && len(stack) == 0 {
				return nil, errors.New("junk after document element")
			}
			n := &node{local: t.Name.Local, attrs: t.Attr}
			if len(stack) == 0 {
				root = n
			} else {
				top := stack[len(stack)-1]
				top.children = append(top.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if !xmlSpace(string(t)) {
					return nil, errors.New("text outside the document element")
				}
				continue
			}
			top := stack[len(stack)-1]
			if len(top.children) == 0 {
				top.text += string(t)
			} else {
				top.children[len(top.children)-1].tail += string(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("no element found")
	}
	if len(stack) > 0 {
		return nil, errors.New("unclosed element at the end of the document")
	}
	return root, nil
}

// The single-byte encodings a feed declares in practice. Anything else is
// refused as malformed.
func charsetReader(label string, in io.Reader) (io.Reader, error) {
	var table func(byte) rune
	switch strings.ToLower(strings.ReplaceAll(label, "_", "-")) {
	case "utf8":
		return in, nil
	case "iso-8859-1", "iso8859-1", "latin-1", "latin1", "l1", "us-ascii", "ascii":
		table = func(b byte) rune { return rune(b) }
	case "windows-1252", "cp1252":
		table = func(b byte) rune {
			if b >= 0x80 && b <= 0x9f {
				return cp1252[b-0x80]
			}
			return rune(b)
		}
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", label)
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	for _, c := range data {
		b.WriteRune(table(c))
	}
	return strings.NewReader(b.String()), nil
}

// cp1252 is 0x80-0x9F in windows-1252; the five it leaves undefined map to
// themselves, as Python's html.unescape maps those character references.
var cp1252 = [32]rune{
	0x20ac, 0x81, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8d, 0x017d, 0x8f,
	0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x9d, 0x017e, 0x0178,
}

// looksLikeHTML is the lane's looks_like_html: an HTML page where a feed
// should be is how a feed dies (a redirect to a web page, status 200).
func looksLikeHTML(raw []byte) bool {
	head := bytes.TrimLeft(raw[:min(len(raw), 1024)], " \t\n\r\v\f")
	if len(head) > 0 && head[0] == 0xef {
		head = bytes.TrimLeft(head[min(len(head), 3):], " \t\n\r\v\f")
	}
	low := bytes.ToLower(head[:min(len(head), 512)])
	return bytes.HasPrefix(low, []byte("<!doctype html")) || bytes.HasPrefix(low, []byte("<html")) ||
		(bytes.Contains(low, []byte("<html")) && !bytes.Contains(low, []byte("<?xml")))
}

type item struct {
	Title     string
	Link      string
	Published *string
	Text      string
}

var tagRE = regexp.MustCompile(`<[^>]+>`)

// textOf is unescape(TAG_RE.sub(" ", "".join(el.itertext()))): a feed's
// HTML is in its text, escaped or in CDATA, and only the words are wanted.
func textOf(n *node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	n.itertext(&b)
	return unescape(tagRE.ReplaceAllString(b.String(), " "))
}

// parseFeed is the lane's parse_feed; every refusal is logged and is an
// empty list, which the caller counts as a failed feed.
func parseFeed(raw []byte, url string, logf func(string, ...any)) []item {
	items := []item{}
	if looksLikeHTML(raw) {
		logf("NOT A FEED %s :: returned an HTML page, not XML - the feed has probably moved or been retired. "+
			"Check where the URL redirects to, and replace it in feeds.txt.", url)
		return items
	}
	// Feeds are untrusted XML. XML-bomb and external-entity attacks need an
	// <!ENTITY> declaration and a real feed has none, so one that does is
	// refused. (Go's decoder expands no declared entity anyway.)
	if bytes.Contains(bytes.ToLower(raw), []byte("<!entity")) {
		logf("PARSE FAIL %s :: the feed declares XML entities, which a real feed does not - refused", url)
		return items
	}
	root, err := parseXML(raw)
	if err != nil {
		logf("PARSE FAIL %s :: malformed XML :: %v", url, err)
		return items
	}
	var entries []*node
	root.iter(func(n *node) {
		if n.local == "item" || n.local == "entry" {
			entries = append(entries, n)
		}
	})
	for _, e := range entries {
		fields := map[string]*node{}
		for _, c := range e.children {
			if _, ok := fields[c.local]; !ok {
				fields[c.local] = c
			}
		}
		title := pyStrip(textOf(fields["title"]))
		link := ""
		if le := fields["link"]; le != nil {
			link = le.href()
			if link == "" {
				link = le.text
			}
			link = pyStrip(link)
		}
		date := ""
		for _, k := range []string{"pubDate", "published", "updated", "date"} {
			if date = textOf(fields[k]); date != "" {
				break
			}
		}
		var published *string
		if t := parseDate(date); t != nil {
			s := t.isoformat()
			published = &s
		}
		body := make([]string, 0, 4)
		for _, k := range []string{"description", "summary", "content", "encoded"} {
			body = append(body, textOf(fields[k]))
		}
		r := []rune(title)
		short := string(r[:min(len(r), 300)])
		items = append(items, item{Title: short, Link: link, Published: published, Text: title + " " + strings.Join(body, " ")})
	}
	return items
}

// unescape is Python's html.unescape. Named references are resolved by Go's
// html package, which follows the same HTML5 table and the same longest
// prefix rule; numeric ones follow Python's own rules, which differ.
func unescape(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	r := []rune(s)
	var b strings.Builder
	for i := 0; i < len(r); {
		if r[i] != '&' {
			b.WriteRune(r[i])
			i++
			continue
		}
		if repl, n := charref(r[i+1:]); n > 0 {
			b.WriteString(repl)
			i += 1 + n
			continue
		}
		b.WriteRune('&')
		i++
	}
	return b.String()
}

// charref matches what follows one "&" against Python's
// &(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?) and returns the
// replacement and how many runes it consumed (0: no match).
func charref(r []rune) (string, int) {
	if len(r) == 0 {
		return "", 0
	}
	if r[0] == '#' {
		hex := len(r) > 1 && (r[1] == 'x' || r[1] == 'X')
		start := 1
		if hex {
			start = 2
		}
		j := start
		for j < len(r) && (asciiDigit(r[j]) || (hex && strings.ContainsRune("abcdefABCDEF", r[j]))) {
			j++
		}
		if j == start {
			return "", 0
		}
		digits := string(r[start:j])
		if j < len(r) && r[j] == ';' {
			j++
		}
		return numericRef(digits, hex), j
	}
	j := 0
	for j < len(r) && j < 32 && !strings.ContainsRune("\t\n\f <&#;", r[j]) {
		j++
	}
	if j == 0 {
		return "", 0
	}
	if j < len(r) && r[j] == ';' {
		j++
	}
	return html.UnescapeString("&" + string(r[:j])), j
}

func numericRef(digits string, hex bool) string {
	base := 10
	if hex {
		base = 16
	}
	num := 0
	for _, c := range digits {
		v := strings.IndexRune("0123456789abcdef", unicode.ToLower(c))
		num = num*base + v
		if num > 0x10ffff {
			return "�"
		}
	}
	switch {
	case num == 0:
		return "�"
	case num == 0x0d:
		return "\r"
	case num >= 0x80 && num <= 0x9f:
		return string(cp1252[num-0x80])
	case num >= 0xd800 && num <= 0xdfff:
		return "�"
	case invalidCodepoint(num):
		return ""
	}
	return string(rune(num))
}

// invalidCodepoint is html._invalid_codepoints: control characters and
// non-characters, which Python's unescape drops.
func invalidCodepoint(n int) bool {
	switch {
	case n >= 0x1 && n <= 0x8, n == 0xb, n >= 0xe && n <= 0x1f, n >= 0x7f && n <= 0x9f, n >= 0xfdd0 && n <= 0xfdef:
		return true
	}
	return n&0xfffe == 0xfffe
}

// wordRune is Python's \w for str: alphanumeric (str.isalnum) or underscore.
func wordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// findCVEs is CVE_RE.findall(text) for \bCVE-\d{4}-\d{4,}\b, case-insensitive,
// with Python's Unicode \d and \b. The sequence number has a four-digit
// minimum and no maximum: a bound would cut a longer ID into a different one.
func findCVEs(text string) []string {
	r := []rune(text)
	var out []string
	for i := 0; i < len(r); i++ {
		if i > 0 && wordRune(r[i-1]) {
			continue
		}
		if i+4 > len(r) || !strings.EqualFold(string(r[i:i+3]), "cve") || r[i+3] != '-' {
			continue
		}
		j := i + 4
		k := j
		for k < len(r) && k < j+4 && unicode.IsDigit(r[k]) {
			k++
		}
		if k != j+4 || k >= len(r) || r[k] != '-' {
			continue
		}
		k++
		d := k
		for d < len(r) && unicode.IsDigit(r[d]) {
			d++
		}
		if d-k < 4 || (d < len(r) && wordRune(r[d])) {
			continue
		}
		out = append(out, string(r[i:d]))
		i = d - 1
	}
	return out
}

// pySpace is Python's str.isspace, which split() and strip() use.
func pySpace(r rune) bool {
	switch {
	case r >= 0x1c && r <= 0x1f, r == 0x85, r == 0xa0:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r) || r == 0x2028 || r == 0x2029
}

func pyStrip(s string) string { return strings.TrimFunc(s, pySpace) }
