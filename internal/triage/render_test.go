package triage

import (
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func sample() *Result {
	why := "Checkout JavaScript is the one asset class this applies to."
	return &Result{
		Schema: Schema, MessageID: "m1", ItemCount: 4, Confidence: "high",
		Items: []Item{
			{
				Title: "AI agent retail campaign", Source: "Gambit Security",
				Relevance: RelevanceLikely, WhyItMightMatter: &why,
				RelevanceReason: "the profile lists Adobe Commerce",
				Summary:         "Operators replaced checkout JavaScript.",
				Indicators:      []string{"cdn.netlfjs[.]com"},
				SuggestedChecks: []string{"Hash the JS served on /checkout"},
				Link:            ptr("https://gambit.example/report"),
			},
			{Title: "Rogue MFA provider", Source: "EY CRTU", Relevance: RelevancePossible,
				SuggestedChecks: []string{"Review Entra external auth methods"}},
			{Title: "SAP BTP abuse", Source: "EY CRTU", Relevance: RelevanceUnlikely,
				Summary:         "Not applicable to our sector.",
				SuggestedChecks: []string{"this should not appear"}},
			{Title: "Unnumbered zero-day claim", Source: "Gambit Security",
				Relevance: RelevanceUnknown},
		},
	}
}

func TestEveryItemAppearsWhateverItsRelevance(t *testing.T) {
	// The agent is forbidden from omitting an item. A renderer that drops the
	// quiet ones commits the same omission one stage later, where nobody is
	// looking for it.
	b := Render(sample(), nil, Extraction{})
	for _, want := range []string{
		"AI agent retail campaign", "Rogue MFA provider",
		"SAP BTP abuse", "Unnumbered zero-day claim",
	} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("text is missing %q", want)
		}
		if !strings.Contains(b.HTML, want) {
			t.Errorf("html is missing %q", want)
		}
	}
}

func TestOnlyLikelyAndPossibleGetTheirDetail(t *testing.T) {
	b := Render(sample(), nil, Extraction{})

	if !strings.Contains(b.Text, "Hash the JS served on /checkout") {
		t.Error("a likely item lost its suggested check")
	}
	if !strings.Contains(b.Text, "Review Entra external auth methods") {
		t.Error("a possible item lost its suggested check")
	}
	if strings.Contains(b.Text, "this should not appear") {
		t.Error("an unlikely item rendered its suggested checks")
	}
	if strings.Contains(b.Text, "Not applicable to our sector") {
		t.Error("an unlikely item rendered its summary")
	}
}

func TestRenderOrdersItemsItselfWithoutVerifyHavingRun(t *testing.T) {
	// A replay, a test, or a second caller that renders an unverified result
	// would otherwise get the agent's arbitrary order with nothing to show
	// anything was wrong.
	r := &Result{Schema: Schema, Confidence: "high", Items: []Item{
		{Title: "d", Relevance: RelevanceUnlikely},
		{Title: "c", Relevance: RelevanceUnknown},
		{Title: "a", Relevance: RelevanceLikely},
		{Title: "b", Relevance: RelevancePossible},
	}}
	b := Render(r, nil, Extraction{})

	var seen []string
	for _, line := range strings.Split(b.Text, "\n") {
		if i := strings.Index(line, "] "); strings.HasPrefix(line, "[") && i > 0 {
			seen = append(seen, strings.TrimSpace(line[i+2:]))
		}
	}
	want := []string{"a", "b", "c", "d"}
	if len(seen) != 4 {
		t.Fatalf("parsed %v from:\n%s", seen, b.Text)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("order = %v, want %v (likely, possible, unknown, unlikely)", seen, want)
		}
	}
}

func TestTheCountSaysHowManyAreWorthALook(t *testing.T) {
	b := Render(sample(), nil, Extraction{})
	if !strings.Contains(b.Text, "(4 found, 2 worth a look)") {
		t.Errorf("header does not summarise correctly:\n%s", firstLine(b.Text))
	}
}

func TestIndicatorsSurviveOnEveryItemAndStayDefanged(t *testing.T) {
	// Indicators are the part a reader can act on without agreeing with any
	// judgement, so they are not gated on relevance. And refanging one would
	// turn a digest into a live link to attacker infrastructure.
	b := Render(sample(), nil, Extraction{})
	for _, form := range []string{b.Text, b.HTML} {
		if !strings.Contains(form, "cdn.netlfjs[.]com") {
			t.Error("the indicator is missing")
		}
		if strings.Contains(form, "cdn.netlfjs.com") {
			t.Error("the indicator was refanged into a live hostname")
		}
	}

	// And on an item nobody judged relevant, which is where it would be
	// cheapest to drop and least likely to be noticed.
	r := sample()
	r.Items[3].Indicators = []string{"155.254.22[.]215"}
	if b := Render(r, nil, Extraction{}); !strings.Contains(b.Text, "155.254.22[.]215") {
		t.Error("an unknown-relevance item lost its indicator")
	}
}

func TestNothingFromTheAdvisoryBecomesAClickableLink(t *testing.T) {
	// This mail arrives at a published address anyone can write to, so a URL
	// in it is a URL an attacker chose. An anchor would make the security
	// team's own digest a phishing delivery mechanism.
	r := sample()
	r.Items[0].Title = `Click <a href="https://evil.example">here</a> now`
	r.Items[0].Link = ptr("https://evil.example/pwn")

	b := Render(r, nil, Extraction{})

	if strings.Contains(b.HTML, "<a href") {
		t.Errorf("an anchor reached the HTML:\n%s", b.HTML)
	}
	if !strings.Contains(b.HTML, "&lt;a href") {
		t.Error("the markup in the title was not escaped")
	}
}

func TestHostileTitlesCannotBreakTheHTML(t *testing.T) {
	r := sample()
	r.Items[0].Title = `</p><script>alert(1)</script><p>`
	r.Items[0].Source = `"onmouseover="alert(2)`

	b := Render(r, nil, Extraction{})

	for _, bad := range []string{"<script>", "</script>", `onmouseover="alert`} {
		if strings.Contains(b.HTML, bad) {
			t.Errorf("unescaped %q reached the HTML", bad)
		}
	}
}

func TestAnInjectionAttemptIsReportedInTheEmail(t *testing.T) {
	// Not only in a log. The recurring failure in this fleet is a component
	// reporting success while doing nothing, and a log nobody opens is the
	// same as no report.
	r := sample()
	r.InjectionAttempt = true
	b := Render(r, nil, Extraction{})

	if !strings.Contains(b.Text, "tried to instruct") {
		t.Errorf("the injection attempt is not in the digest:\n%s", b.Text)
	}
}

func TestFabricationsAndOmissionsAreReportedInTheEmail(t *testing.T) {
	vs := []Violation{
		{Kind: "fabricated", Field: "indicators", Value: "invented[.]com", Why: "x"},
		{Kind: "dropped", Field: "techniques", Value: "T1556.006", Why: "y"},
	}
	b := Render(sample(), vs, Extraction{})

	if !strings.Contains(b.Text, "invented[.]com") {
		t.Error("a fabricated value was removed without being reported")
	}
	if !strings.Contains(b.Text, "T1556.006") {
		t.Error("a dropped technique was not reported")
	}
}

func TestTheFooterOrderIsStableAcrossRuns(t *testing.T) {
	// Go randomises map iteration. A digest whose wording shuffles between two
	// runs over identical input teaches the reader that differences do not
	// mean anything - which is the opposite of what a daily report is for.
	vs := []Violation{
		{Kind: "dropped", Field: "indicators", Value: "a[.]com"},
		{Kind: "dropped", Field: "cves", Value: "CVE-2026-1"},
		{Kind: "dropped", Field: "techniques", Value: "T1190"},
	}
	first := Render(sample(), vs, Extraction{}).Text
	for i := 0; i < 20; i++ {
		if got := Render(sample(), vs, Extraction{}).Text; got != first {
			t.Fatalf("run %d differed from run 0", i)
		}
	}
}

func TestARefusalStillShowsWhatPatternMatchingFound(t *testing.T) {
	// A refusal is a legitimate outcome. Rendering nothing would make it
	// indistinguishable from a quiet day, which is the one reading that must
	// not be available.
	r := &Result{
		Schema: Schema, MessageID: "m1", Refused: true, Confidence: "low",
		Notes: []string{"truncated mid-item"},
	}
	e := Extraction{
		CVEs:       []string{"CVE-2026-94127"},
		Indicators: []string{"cdn.netlfjs[.]com"},
	}
	b := Render(r, nil, e)

	if !strings.Contains(b.Text, "NOT read") {
		t.Error("the digest does not say the items were not analysed")
	}
	for _, want := range []string{"CVE-2026-94127", "cdn.netlfjs[.]com", "truncated mid-item"} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("a refusal lost %q", want)
		}
	}
}

func TestLowConfidenceIsSaidOutLoud(t *testing.T) {
	r := sample()
	r.Confidence = "low"
	if b := Render(r, nil, Extraction{}); !strings.Contains(b.Text, "LOW confidence") {
		t.Error("low confidence was not surfaced")
	}
}

func TestAQuietDayRendersSomethingRatherThanNothing(t *testing.T) {
	// An empty section with a heading says "we looked". No section at all is
	// indistinguishable from the lane having failed to run.
	r := &Result{Schema: Schema, MessageID: "m", Confidence: "high"}
	b := Render(r, nil, Extraction{})

	if !strings.Contains(b.Text, Heading) {
		t.Error("the heading disappeared on a quiet day")
	}
	if !strings.Contains(b.Text, "Nothing without a CVE") {
		t.Errorf("no explanation of the empty section:\n%s", b.Text)
	}
}

func TestRelevanceIsAWordNotOnlyAColour(t *testing.T) {
	// These get forwarded, printed, and read on clients that strip styling.
	b := Render(sample(), nil, Extraction{})
	for _, want := range []string{"LIKELY", "POSSIBLE", "UNLIKELY", "UNKNOWN"} {
		if !strings.Contains(b.HTML, want) {
			t.Errorf("the HTML does not spell out %q", want)
		}
	}
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}
