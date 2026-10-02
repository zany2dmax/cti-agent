package triage

import (
	"fmt"
	"html"
	"strings"
)

// Block is the digest section in both forms the mail needs.
//
// Rendered here rather than in brief.py so that the decisions - what is loud,
// what is quiet, what is never dropped, what is never made clickable - live
// next to the tests that pin them. brief.py inserts the strings and makes no
// judgements of its own.
type Block struct {
	Text string
	HTML string
}

// Heading is what the section is called in the digest. Named rather than
// inlined because the subject-line logic and the runbook both refer to it.
const Heading = "Items with no CVE"

// Render builds the digest section.
//
// # WHAT IS LOUD AND WHAT IS QUIET
//
// Every item appears. `likely` and `possible` get their reason and their
// suggested checks; `unknown` and `unlikely` get one line each. That split is
// the operator's: the email says "we have this, it is risky, you should know",
// and anything that is not that is a line, not a paragraph.
//
// Quiet is not absent. The agent's own instructions forbid it from omitting an
// item, and a renderer that drops the quiet ones would reintroduce exactly the
// omission the agent is not allowed to make - just one stage later, where
// nobody is looking.
//
// # WHAT IS NEVER CLICKABLE
//
// Nothing from the body becomes an anchor. Indicators stay defanged as
// written, and source links render as plain text. This arrives at a published
// address that anyone can mail, so a URL in it is a URL an attacker chose. A
// security digest that turns attacker-supplied text into a one-click link is a
// phishing delivery mechanism with the security team's name in the From field.
func Render(r *Result, vs []Violation, e Extraction) Block {
	var t, h strings.Builder

	// Sorted here as well as in Verify. The ordering is a property of the
	// output, not of the verification, and a caller that renders an unverified
	// result - a replay, a test, a future second caller - would otherwise get
	// the agent's arbitrary order with no indication anything was wrong.
	// Sorting twice costs nothing; depending on a previous call costs a bug
	// that only appears in the second place this is used.
	sortItems(r.Items)

	worth := 0
	for _, it := range r.Items {
		if it.Relevance == RelevanceLikely || it.Relevance == RelevancePossible {
			worth++
		}
	}

	head := fmt.Sprintf("%s (%d found, %d worth a look)", Heading, len(r.Items), worth)
	fmt.Fprintf(&t, "%s\n%s\n\n", head, strings.Repeat("-", len(head)))
	fmt.Fprintf(&h, "<h3>%s</h3>\n", html.EscapeString(head))

	if r.Refused {
		// A refusal is a legitimate outcome, and the deterministic extraction
		// still has to reach the reader. Saying "not analysed" and then showing
		// the regex findings is the honest version of this; showing nothing
		// would make a refusal indistinguishable from a quiet day.
		renderRefusal(&t, &h, r, e)
		return Block{Text: t.String(), HTML: h.String()}
	}

	if len(r.Items) == 0 {
		t.WriteString("Nothing without a CVE in today's advisories.\n")
		h.WriteString("<p>Nothing without a CVE in today's advisories.</p>\n")
	}

	for _, it := range r.Items {
		detailed := it.Relevance == RelevanceLikely || it.Relevance == RelevancePossible

		// Text form.
		fmt.Fprintf(&t, "[%s] %s", strings.ToUpper(it.Relevance), it.Title)
		if it.Source != "" {
			fmt.Fprintf(&t, " - %s", it.Source)
		}
		t.WriteString("\n")

		// HTML form. The relevance is a word, not only a colour: these get
		// forwarded, printed and read on clients that strip styling.
		fmt.Fprintf(&h, "<p><strong>%s</strong> &mdash; %s",
			html.EscapeString(strings.ToUpper(it.Relevance)), html.EscapeString(it.Title))
		if it.Source != "" {
			fmt.Fprintf(&h, " &mdash; %s", html.EscapeString(it.Source))
		}
		h.WriteString("<br>\n")

		if detailed {
			writeDetail(&t, &h, it)
		}

		// Indicators appear for every item regardless of relevance. They are
		// the part a person can act on without agreeing with any judgement.
		if len(it.Indicators) > 0 {
			line := "indicators: " + strings.Join(it.Indicators, ", ")
			fmt.Fprintf(&t, "    %s\n", line)
			fmt.Fprintf(&h, "&nbsp;&nbsp;<code>%s</code><br>\n", html.EscapeString(line))
		}

		t.WriteString("\n")
		h.WriteString("</p>\n")
	}

	renderFooter(&t, &h, r, vs)
	return Block{Text: t.String(), HTML: h.String()}
}

func writeDetail(t, h *strings.Builder, it Item) {
	if s := strings.TrimSpace(it.Summary); s != "" {
		fmt.Fprintf(t, "    %s\n", s)
		fmt.Fprintf(h, "&nbsp;&nbsp;%s<br>\n", html.EscapeString(s))
	}
	if it.WhyItMightMatter != nil {
		if s := strings.TrimSpace(*it.WhyItMightMatter); s != "" {
			fmt.Fprintf(t, "    %s\n", s)
			fmt.Fprintf(h, "&nbsp;&nbsp;%s<br>\n", html.EscapeString(s))
		}
	}
	if s := strings.TrimSpace(it.RelevanceReason); s != "" {
		fmt.Fprintf(t, "    why: %s\n", s)
		fmt.Fprintf(h, "&nbsp;&nbsp;<em>why: %s</em><br>\n", html.EscapeString(s))
	}
	for _, c := range it.SuggestedChecks {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		fmt.Fprintf(t, "    -> %s\n", c)
		fmt.Fprintf(h, "&nbsp;&nbsp;&rarr; %s<br>\n", html.EscapeString(c))
	}
	// Plain text, never an anchor. See the Render comment.
	if it.Link != nil {
		if l := strings.TrimSpace(*it.Link); l != "" {
			fmt.Fprintf(t, "    source: %s\n", l)
			fmt.Fprintf(h, "&nbsp;&nbsp;source: <code>%s</code><br>\n", html.EscapeString(l))
		}
	}
}

func renderRefusal(t, h *strings.Builder, r *Result, e Extraction) {
	const msg = "The analysis step declined to parse today's advisories, so the " +
		"items below were NOT read by anything. This is what pattern matching " +
		"found on its own."
	fmt.Fprintf(t, "%s\n\n", msg)
	fmt.Fprintf(h, "<p><strong>%s</strong></p>\n", html.EscapeString(msg))

	for _, f := range []struct {
		name string
		vals []string
	}{
		{"CVEs", e.CVEs},
		{"techniques", e.Techniques},
		{"indicators", e.Indicators},
	} {
		if len(f.vals) == 0 {
			continue
		}
		line := f.name + ": " + strings.Join(f.vals, ", ")
		fmt.Fprintf(t, "  %s\n", line)
		fmt.Fprintf(h, "<p><code>%s</code></p>\n", html.EscapeString(line))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(t, "  note: %s\n", n)
		fmt.Fprintf(h, "<p>note: %s</p>\n", html.EscapeString(n))
	}
}

// renderFooter reports on the analysis itself rather than on any advisory.
//
// Every line here is a case where the system did something other than what it
// was supposed to. They are in the email, not only in a log, because this
// fleet's recurring failure is a component reporting success while doing
// nothing - and a log nobody opens is the same as no report at all.
func renderFooter(t, h *strings.Builder, r *Result, vs []Violation) {
	var notes []string

	if r.InjectionAttempt {
		notes = append(notes, "The content tried to instruct the analysis step. "+
			"It was treated as data. An advisory containing instructions aimed "+
			"at an AI reader is itself worth looking at.")
	}
	notes = append(notes, r.Notes...)
	if f := Fabricated(vs); len(f) > 0 {
		var bad []string
		for _, v := range f {
			bad = append(bad, v.Value)
		}
		notes = append(notes, fmt.Sprintf(
			"%d value(s) reported by the analysis step were not in the source "+
				"text and were removed: %s", len(bad), strings.Join(bad, ", ")))
	}
	// Fixed order, not map order. Go randomises map iteration, so ranging over
	// Dropped() directly would reorder the footer between two runs over
	// identical input - and a digest that differs from yesterday's for no
	// reason teaches the reader that differences do not mean anything.
	dropped := Dropped(vs)
	for _, field := range []string{"cves", "techniques", "indicators"} {
		vals := dropped[field]
		if len(vals) == 0 {
			continue
		}
		notes = append(notes, fmt.Sprintf(
			"the analysis step did not mention %d %s that pattern matching found, "+
				"listed here instead: %s",
			len(vals), field, strings.Join(vals, ", ")))
	}
	if r.Confidence == "low" {
		notes = append(notes, "The analysis step reported LOW confidence in the "+
			"parse as a whole. Treat the structure above as unreliable; the "+
			"indicators are still verbatim from the source.")
	}

	if len(notes) == 0 {
		return
	}
	t.WriteString("About this analysis:\n")
	h.WriteString("<p><strong>About this analysis:</strong></p>\n<ul>\n")
	for _, n := range notes {
		fmt.Fprintf(t, "  - %s\n", n)
		fmt.Fprintf(h, "<li>%s</li>\n", html.EscapeString(n))
	}
	h.WriteString("</ul>\n")
}
