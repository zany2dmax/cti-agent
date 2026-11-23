package enrich

// "Which product is this about?" - Chrome, Safari, PHP - on every finding and
// fleet ticket. Three sources the fleet already has, in order of trust:
//
//  1. The CISA KEV catalog's vendorProject and product: one clean name,
//     written by a person, e.g. "Google" / "Chromium V8".
//  2. NVD's CPE configuration: the vulnerable products as vendor:product
//     pairs, e.g. cpe:2.3:a:google:chrome. Missing for a CVE NVD has not
//     analysed yet, which is common in its first weeks.
//  3. The scanner's own detection titles, from the report's last column:
//     "Google Chrome Prior to 131.0 Multiple Vulnerabilities", cut down to
//     the product.
//
// When none has an answer the product is "" and the email says "product not
// identified". Nothing guesses one from the description text.

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// CPE names are lower case. These words read as acronyms; the rest are
// capitalised. A wrong case here is cosmetic, never a wrong product.
var cpeUpper = map[string]bool{}

func init() {
	for _, w := range strings.Fields("php http https ssh ssl tls sql iis dns vpn api os xml pdf smb rdp " +
		"ldap nas jdk jre ftp cms ip wan lan ui bios uefi vm esxi nfs snmp ntp ssl_vpn") {
		cpeUpper[w] = true
	}
}

var cpeNames = map[string]string{
	"macos": "macOS", "mac_os_x": "macOS", "iphone_os": "iOS", "ipados": "iPadOS",
	"watchos": "watchOS", "tvos": "tvOS", "visionos": "visionOS", "node.js": "Node.js",
}

// productMax is how many names are given before "+N more".
const productMax = 3

var (
	cpeEscape = regexp.MustCompile(`\\(.)`)
	cpeSplit  = regexp.MustCompile(`[_\s]+`)
)

// cpeUnescape undoes CPE 2.3's backslash escapes: node\.js -> node.js.
func cpeUnescape(s string) string { return cpeEscape.ReplaceAllString(s, "$1") }

func cpeWords(s string) string {
	if n, ok := cpeNames[s]; ok {
		return n
	}
	var words []string
	for _, w := range cpeSplit.Split(s, -1) {
		if w == "" {
			continue
		}
		if cpeUpper[strings.ToLower(w)] {
			words = append(words, strings.ToUpper(w))
			continue
		}
		r, n := utf8.DecodeRuneInString(w)
		words = append(words, strings.ToUpper(string(r))+w[n:])
	}
	return strings.Join(words, " ")
}

// ProductName is one readable name from a vendor and a product. The vendor
// is dropped when the product already starts with it, so php:php reads "PHP"
// and Microsoft / "Microsoft Exchange Server" does not say Microsoft twice.
func ProductName(vendor, product string) string {
	v := strings.Join(strings.Fields(vendor), " ")
	p := strings.Join(strings.Fields(product), " ")
	if p == "" {
		return v
	}
	if v == "" || strings.HasPrefix(strings.ToLower(p), strings.ToLower(v)) {
		return p
	}
	return v + " " + p
}

// nvdConfigurations is the part of an NVD CVE record CPEProducts reads.
type nvdConfigurations []struct {
	Nodes []struct {
		CPEMatch []struct {
			Vulnerable bool   `json:"vulnerable"`
			Criteria   string `json:"criteria"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}

// CPEProducts is the vulnerable (vendor, product) pairs of an NVD record, in
// order, once each. Only cpeMatch entries marked vulnerable count: the others
// say what the product runs on ("Chrome on Windows"), and naming Windows for
// a Chrome bug would send the reader to the wrong machines.
func CPEProducts(conf nvdConfigurations) [][]string {
	seen := map[[2]string]bool{}
	out := [][]string{}
	for _, c := range conf {
		for _, node := range c.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				// cpe:2.3:<part>:<vendor>:<product>:... An escaped colon inside
				// a field is rare enough that a split is fine: the worst case
				// is an odd-looking name, not a wrong one.
				parts := strings.Split(m.Criteria, ":")
				if len(parts) < 5 || parts[0] != "cpe" {
					continue
				}
				pair := [2]string{cpeUnescape(parts[3]), cpeUnescape(parts[4])}
				bad := false
				for _, x := range pair {
					if x == "*" || x == "-" || x == "" {
						bad = true
					}
				}
				if bad || seen[pair] {
					continue
				}
				seen[pair] = true
				out = append(out, []string{pair[0], pair[1]})
			}
		}
	}
	return out
}

// A scanner title names the product, then says what is wrong with it. The
// product is the part before the first of these words; a title that does not
// split cleanly gives no name rather than a long or odd one.
var (
	titleFor = regexp.MustCompile(`(?i)^(?P<who>.+?)\s+(?:Security\s+)?(?:Updates?|Notification|Advisory|Patch)` +
		`\s+for\s+(?P<what>.+)$`)
	titleCut = regexp.MustCompile(`(?i)\s+(?:Prior\s+to\b|Before\b|Versions?\b|Multiple\b|Remote\b|Security\b|` +
		`Cumulative\b|Critical\b|Denial\b|Information\b|Privilege\b|Elevation\b|` +
		`Arbitrary\b|Cross[- ]Site\b|SQL\s+Injection\b|Buffer\b|Heap\b|Stack\b|` +
		`Use[- ]After[- ]Free\b|Out[- ]of[- ]Bounds\b|Type\s+Confusion\b|Integer\b|` +
		`Command\s+Injection\b|Path\s+Traversal\b|Authentication\b|Unspecified\b|` +
		`Vulnerabilit|Update\b|Patch\b|\(|-\s|:)`)
	dateish = regexp.MustCompile(`(?i)^(?:January|February|March|April|May|June|July|August|` +
		`September|October|November|December|\d)`)
)

const titleProductMax = 60

func cutTitle(s string) string {
	if loc := titleCut.FindStringIndex(s); loc != nil {
		return s[:loc[0]]
	}
	return s
}

// ProductFromTitle is the product named in a scanner detection title, or "".
//
//	"Google Chrome Prior to 131.0 Multiple Vulnerabilities" -> "Google Chrome"
//	"Red Hat Update for kernel (RHSA-2026:1234)"           -> "kernel (Red Hat)"
//	"Microsoft Windows Security Update for November 2026"  -> "Microsoft Windows"
func ProductFromTitle(title string) string {
	t := strings.Join(strings.Fields(title), " ")
	if t == "" {
		return ""
	}
	var name string
	if m := titleFor.FindStringSubmatch(t); m != nil {
		who := strings.TrimSpace(m[titleFor.SubexpIndex("who")])
		what := strings.TrimSpace(cutTitle(m[titleFor.SubexpIndex("what")]))
		// "Red Hat Update for kernel" is about the kernel, as Red Hat ships
		// it; "... Security Update for November 2026" is about the vendor's
		// product.
		if what == "" || dateish.MatchString(what) {
			name = who
		} else {
			name = what + " (" + who + ")"
		}
	} else {
		name = strings.TrimSpace(cutTitle(t))
	}
	name = strings.Trim(name, " -,:")
	if n := utf8.RuneCountInString(name); n < 2 || n > titleProductMax || dateish.MatchString(name) {
		return ""
	}
	return name
}

// ProductFor names what a finding is about and where the name came from:
// CISA KEV, then NVD, then the scanner's detection titles. ("", "") when none
// knows.
func ProductFor(kevVendor, kevProduct string, cpe [][]string, titles []string, provider string) (string, string) {
	if name := ProductName(kevVendor, kevProduct); name != "" {
		return name, "CISA KEV"
	}
	var names []string
	add := func(n string) {
		if n == "" {
			return
		}
		for _, x := range names {
			if x == n {
				return
			}
		}
		names = append(names, n)
	}
	for _, pair := range cpe {
		if len(pair) == 2 {
			add(ProductName(cpeWords(pair[0]), cpeWords(pair[1])))
		}
	}
	source := "NVD"
	if len(names) == 0 {
		for _, t := range titles {
			add(ProductFromTitle(t))
		}
		prov := strings.TrimSpace(provider)
		switch {
		case strings.ToLower(prov) == "qualys":
			source = "Qualys"
		case prov != "":
			source = prov
		default:
			source = "scanner"
		}
	}
	if len(names) == 0 {
		return "", ""
	}
	shown := names
	if len(shown) > productMax {
		shown = shown[:productMax]
	}
	s := strings.Join(shown, ", ")
	if len(names) > productMax {
		s += fmt.Sprintf(" +%d more", len(names)-productMax)
	}
	return s, source
}
