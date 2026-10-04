package defender

import (
	"html"
	"regexp"
	"strings"
	"time"
)

// AttackPath is one Defender for Cloud notification, reduced to what it
// actually tells us.
//
// Resource and CVEs are deliberately NOT here. The email does not contain
// them, and a struct with empty fields for them would invite a renderer to
// print "Resource: " and let a reader conclude there was no resource. They
// come from the ARM lookup or they do not exist yet.
type AttackPath struct {
	Title       string
	Description string
	RiskLevel   string // as Microsoft words it: High, Medium, Low
	Detected    time.Time

	Subscriptions []string
	RiskFactors   []string
	AttackStory   []string
	ID            string

	// PortalURL is set only when the link verified as portal.azure.com.
	PortalURL string
	// LinkProblem explains why PortalURL is empty. Reported, never swallowed:
	// a Defender notification whose link points somewhere else is a finding.
	LinkProblem string
}

// Complete reports whether enough was parsed to be worth rendering.
//
// The ID is the load-bearing field - it is what the ARM lookup keys on, and
// without it the notification can never be resolved to a resource. A parse
// that lost it should be reported as a parse failure rather than rendered as
// a thin finding.
func (a AttackPath) Complete() bool {
	return a.ID != "" && a.Title != ""
}

// Labels in the "Attack path details" table. Matched exactly, after tag
// stripping and entity decoding.
//
// Keyed on label text rather than on markup structure because Microsoft
// rewrites the HTML template without notice and has no stable class names or
// data attributes. The labels are what a human reads, so they are the part
// least likely to change silently - and when they do change, the parse comes
// back empty and says so, rather than binding to the wrong cell.
const (
	labelScopeIDs     = "Scope IDs"
	labelRiskFactors  = "Risk factors"
	labelAttackStory  = "Attack story"
	labelAttackPathID = "Attack path ID"
	labelRiskLevel    = "Risk level:"
	labelDetectedBy   = "Detected by"
)

var knownLabels = []string{
	labelScopeIDs, labelRiskFactors, labelAttackStory,
	labelAttackPathID, labelRiskLevel, labelDetectedBy,
}

var (
	// The anchor whose text is "View the attack path". Non-greedy and bounded
	// so a later anchor cannot be captured by a runaway match.
	attackLinkRE = regexp.MustCompile(
		`(?is)<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>\s*View the attack path`)

	// Steps in the attack story: "1- Attacker can ...", "2- ...".
	storyStepRE = regexp.MustCompile(`^\d+\s*-\s*(.+)$`)

	guidRE = regexp.MustCompile(
		`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

	tagRE       = regexp.MustCompile(`(?s)<[^>]*>`)
	blockEndRE  = regexp.MustCompile(`(?i)<br\s*/?>|</(p|div|tr|td|th|h[1-6]|li|ul)>`)
	// Spelled out, because Go's regexp is RE2 and RE2 has no backreferences.
	// The natural way to write this - `<(style|script|head)[^>]*>.*?</\1>` -
	// compiles fine in Python and panics at init here:
	//
	//   invalid escape sequence: `\1`
	//
	// It panicked rather than silently misbehaving, which is the good case;
	// the cost was a full ship cycle to find out.
	dropBlockRE = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>` +
		`|<script[^>]*>.*?</script>` +
		`|<head[^>]*>.*?</head>`)

	// Proofpoint injects a banner div whose id carries a per-message suffix.
	// Removing it keeps its wording out of the parsed text, where "Caution:
	// this email originated outside..." would otherwise read as content.
	pfptRE = regexp.MustCompile(`(?is)<div[^>]+id=["']?pfptBanner[^>]*>.*?</div>`)
)

// Parse reads the HTML body of a notification.
//
// Returns the attack path and a list of problems. Problems are not errors:
// a notification that parsed most of the way is still worth reporting, and
// the problems travel to the digest so a template change announces itself
// instead of showing up as a quietly thinner email.
func Parse(body string) (AttackPath, []string) {
	var a AttackPath
	var problems []string

	// The link comes out of the raw HTML, before tag stripping destroys it.
	if m := attackLinkRE.FindStringSubmatch(body); m != nil {
		if u, err := UnwrapPortalLink(html.UnescapeString(m[1])); err == nil {
			a.PortalURL = u
		} else {
			a.LinkProblem = err.Error()
			problems = append(problems,
				"the 'View the attack path' link did not resolve to "+
					PortalHost+": "+err.Error())
		}
	} else {
		problems = append(problems, "no 'View the attack path' link found")
	}

	lines := textLines(body)
	fields := labelled(lines)

	a.Title, a.Description = titleAndDescription(lines)
	if a.Title == "" {
		problems = append(problems, "could not find the attack path title")
	}

	a.ID = firstGUID(fields[labelAttackPathID])
	if a.ID == "" {
		problems = append(problems, "could not find the attack path ID - "+
			"without it this cannot be resolved to a resource")
	}

	for _, s := range fields[labelScopeIDs] {
		if g := guidRE.FindString(s); g != "" {
			a.Subscriptions = append(a.Subscriptions, g)
		}
	}
	if len(a.Subscriptions) == 0 {
		problems = append(problems, "no subscription found in Scope IDs")
	}

	a.RiskFactors = fields[labelRiskFactors]
	for _, s := range fields[labelAttackStory] {
		if m := storyStepRE.FindStringSubmatch(s); m != nil {
			a.AttackStory = append(a.AttackStory, strings.TrimSpace(m[1]))
		} else if s != "" {
			a.AttackStory = append(a.AttackStory, s)
		}
	}

	a.RiskLevel, a.Detected = riskAndTime(lines, fields)
	if a.RiskLevel == "" {
		problems = append(problems, "could not find the risk level")
	}

	return a, problems
}

// textLines reduces the HTML to the lines a reader would see.
func textLines(body string) []string {
	s := dropBlockRE.ReplaceAllString(body, " ")
	s = pfptRE.ReplaceAllString(s, " ")
	s = blockEndRE.ReplaceAllString(s, "\n")
	s = tagRE.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	// Microsoft's footer carries zero-width spaces; they would otherwise make
	// an exact label comparison fail for reasons invisible in a diff.
	s = strings.NewReplacer("\u200b", "", "\u00a0", " ", "\ufeff", "").Replace(s)

	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.Join(strings.Fields(l), " "); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// labelled groups the lines following each known label, up to the next one.
//
// Order-independent on purpose. The table's row order is a layout decision and
// has already changed once in the wild; the labels themselves are what a human
// reads and are far more stable.
func labelled(lines []string) map[string][]string {
	// Without a terminator the LAST label swallows everything after it - the
	// call-to-action, the Microsoft postal address, the privacy line. Observed:
	// "Attack path ID" came back with three values, of which two were footer.
	// firstGUID happened to pick the right one, which is the kind of accident
	// that works until the footer contains something that looks like a value.
	//
	// So collection stops at the call to action, and no label may collect more
	// than a table cell plausibly holds.
	const maxValues = 12
	terminators := []string{"view the attack path", "privacy statement", "microsoft corporation"}

	out := map[string][]string{}
	current := ""
	for _, l := range lines {
		low := strings.ToLower(l)
		stop := false
		for _, t := range terminators {
			if strings.HasPrefix(low, t) {
				stop = true
				break
			}
		}
		if stop {
			current = ""
			continue
		}
		if lbl, ok := matchLabel(l); ok {
			current = lbl
			continue
		}
		if current != "" && len(out[current]) < maxValues {
			out[current] = append(out[current], l)
		}
	}
	return out
}

func matchLabel(line string) (string, bool) {
	t := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ":"))
	for _, l := range knownLabels {
		if strings.EqualFold(t, strings.TrimSuffix(l, ":")) {
			return l, true
		}
	}
	return "", false
}

// titleAndDescription finds the attack path name.
//
// Located by position relative to the subject line rather than by CSS class:
// Microsoft's class names ("margin-bottom-0 no-wrap") describe layout, and
// binding to them means a visual redesign silently empties this field.
func titleAndDescription(lines []string) (string, string) {
	const subject = "found potential attack path in your environment"
	for i, l := range lines {
		if !strings.Contains(strings.ToLower(l), subject) {
			continue
		}
		// The first following line that is not the banner and not a label.
		for j := i + 1; j < len(lines) && j < i+6; j++ {
			if _, isLabel := matchLabel(lines[j]); isLabel {
				continue
			}
			if strings.Contains(strings.ToUpper(lines[j]), "RISK LEVEL") {
				continue
			}
			desc := ""
			if j+1 < len(lines) {
				if _, isLabel := matchLabel(lines[j+1]); !isLabel {
					desc = lines[j+1]
				}
			}
			return lines[j], desc
		}
	}
	return "", ""
}

// riskAndTime reads the severity and the detection timestamp.
//
// The banner ("HIGH RISK LEVEL") and the card ("Risk level:" / "High") say the
// same thing twice. The card wins because it is the one Microsoft words in
// sentence case; the banner is the fallback for when the card is missing.
func riskAndTime(lines []string, fields map[string][]string) (string, time.Time) {
	level := ""
	if v := fields[labelRiskLevel]; len(v) > 0 {
		level = v[0]
	}
	if level == "" {
		for _, l := range lines {
			if u := strings.ToUpper(l); strings.HasSuffix(strings.TrimSpace(u), "RISK LEVEL") {
				level = sentenceCase(strings.TrimSpace(
					strings.TrimSuffix(strings.TrimSpace(u), "RISK LEVEL")))
				break
			}
		}
	}

	// Several layouts, because the hour is not zero-padded and the month name
	// is spelled out. A timestamp we cannot read is left zero rather than
	// guessed - the caller falls back to the message's own received time,
	// which is at least true about something.
	for _, l := range lines {
		for _, layout := range []string{
			"January 2, 2006 15:04 MST",
			"January 2, 2006 3:04 MST",
			"January 2, 2006 15:04:05 MST",
			"2 January 2006 15:04 MST",
		} {
			if t, err := time.Parse(layout, strings.TrimSpace(l)); err == nil {
				return level, t.UTC()
			}
		}
	}
	return level, time.Time{}
}

// sentenceCase turns the banner's HIGH into High.
//
// Hand-rolled rather than strings.Title, which is deprecated, or the
// golang.org/x/text casing package, which would be this module's first
// dependency. The input is one ASCII severity word from a fixed set.
func sentenceCase(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func firstGUID(vals []string) string {
	for _, v := range vals {
		if g := guidRE.FindString(v); g != "" {
			return g
		}
	}
	return ""
}
