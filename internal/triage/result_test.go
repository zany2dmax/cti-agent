package triage

import (
	"strings"
	"testing"
)

// A small synthetic advisory. Deliberately NOT a real one: the advisories this
// lane reads are commercial and the repository is public.
const advisory = `Gambit Security Daily Roundup - 23 September 2026

1. AI agent retail campaign
Operators replaced checkout JavaScript on Adobe Commerce storefronts. The
loader was served from cdn.netlfjs[.]com and beaconed to 155.254.22[.]215.
Mapped to T1190 and T1059.007.

2. Rogue external MFA provider
Attackers registered an external authentication method in Entra ID. See
T1556.006. No CVE assigned.

3. Citrix NetScaler scanning
Opportunistic scanning for CVE-2026-94127.
`

func result(items ...Item) *Result {
	return &Result{
		Schema: Schema, MessageID: "m1", ItemCount: len(items),
		Items: items, Confidence: "high",
	}
}

func item(title, relevance string, cves, techniques, indicators, evidence []string) Item {
	return Item{
		Title: title, Source: "Gambit Security", Relevance: relevance,
		CVEs: cves, Techniques: techniques, Indicators: indicators, Evidence: evidence,
	}
}

func TestAFabricatedIndicatorIsRemovedAndReported(t *testing.T) {
	// The reason this matters more than it looks: an indicator that reaches the
	// digest is an indicator somebody may block. A hallucinated domain is a
	// self-inflicted outage with a security team's name on it.
	r := result(item("AI agent retail campaign", RelevanceLikely,
		nil, nil,
		[]string{"cdn.netlfjs[.]com", "evil-invented-domain[.]com"}, nil))

	v := Verify(r, advisory, Extraction{}, ProfileFilled)

	if got := r.Items[0].Indicators; len(got) != 1 || got[0] != "cdn.netlfjs[.]com" {
		t.Errorf("the invented indicator survived: %v", got)
	}
	f := Fabricated(v)
	if len(f) != 1 || f[0].Value != "evil-invented-domain[.]com" {
		t.Fatalf("the fabrication was not reported: %+v", v)
	}
	if !strings.Contains(f[0].Why, "does not appear") {
		t.Errorf("the reason does not say what is wrong: %q", f[0].Why)
	}
}

func TestDefangingMustSurviveVerificationExactly(t *testing.T) {
	// "Tidying" cdn.netlfjs[.]com to cdn.netlfjs.com would make it a live link
	// in an HTML email. The check is literal containment for exactly this
	// reason: the refanged form is NOT in the source, so it is caught.
	r := result(item("x", RelevanceUnknown, nil, nil,
		[]string{"cdn.netlfjs.com", "155.254.22.215"}, nil))

	Verify(r, advisory, Extraction{}, ProfileFilled)

	if len(r.Items[0].Indicators) != 0 {
		t.Errorf("refanged indicators were accepted: %v", r.Items[0].Indicators)
	}
}

func TestCaseDifferencesAreNotTreatedAsFabrication(t *testing.T) {
	// Advisories are inconsistent about identifier case. Accusing the agent of
	// inventing "cve-2026-94127" when the body says "CVE-2026-94127" would be a
	// false positive, and a check that cries wolf gets ignored.
	r := result(item("x", RelevanceUnknown,
		[]string{"cve-2026-94127"}, []string{"t1190"}, nil, nil))

	if v := Fabricated(Verify(r, advisory, Extraction{}, ProfileFilled)); len(v) != 0 {
		t.Errorf("a case difference was called a fabrication: %+v", v)
	}
}

func TestWhatTheAgentDroppedIsReportedAnyway(t *testing.T) {
	// The agent is explicitly forbidden from omitting things, but "forbidden"
	// is not "prevented". An omission is invisible downstream - nothing after
	// this point knows the item existed - so the extractor's findings are the
	// backstop.
	e := Extraction{
		CVEs:       []string{"CVE-2026-94127"},
		Techniques: []string{"T1190", "T1556.006", "T1059.007"},
		Indicators: []string{"cdn.netlfjs[.]com", "155.254.22[.]215"},
	}
	r := result(item("AI agent retail campaign", RelevanceLikely,
		nil, []string{"T1190"}, []string{"cdn.netlfjs[.]com"}, nil))

	d := Dropped(Verify(r, advisory, e, ProfileFilled))

	if len(d["cves"]) != 1 || d["cves"][0] != "CVE-2026-94127" {
		t.Errorf("a dropped CVE was not reported: %v", d["cves"])
	}
	if len(d["techniques"]) != 2 {
		t.Errorf("dropped techniques = %v, want T1059.007 and T1556.006", d["techniques"])
	}
	if len(d["indicators"]) != 1 || d["indicators"][0] != "155.254.22[.]215" {
		t.Errorf("a dropped indicator was not reported: %v", d["indicators"])
	}
}

func TestAnIndicatorCountsAsKeptWhicheverItemCarriesIt(t *testing.T) {
	// The agent decides which item an indicator belongs to, and it may well
	// disagree with the extractor about that. Only a DISAPPEARANCE matters.
	e := Extraction{Indicators: []string{"cdn.netlfjs[.]com"}}
	r := result(
		item("first", RelevanceUnknown, nil, nil, nil, nil),
		item("second", RelevanceUnknown, nil, nil, []string{"cdn.netlfjs[.]com"}, nil),
	)
	if d := Dropped(Verify(r, advisory, e, ProfileFilled)); len(d) != 0 {
		t.Errorf("an indicator attributed to another item was called dropped: %v", d)
	}
}

func TestAnUnfilledProfileForcesUnknownWhateverTheAgentSaid(t *testing.T) {
	// The instructions ask the agent to do this itself. Asking is not enough:
	// the whole point of the sentinel is that an unfilled profile reads fine to
	// a model, which then returns a confident "unlikely" for a campaign aimed
	// straight at us. Code decides, not the model.
	for _, p := range []ProfileState{ProfileMissing, ProfileTemplate} {
		r := result(
			item("a", RelevanceLikely, nil, nil, nil, nil),
			item("b", RelevanceUnlikely, nil, nil, nil, nil),
		)
		v := Verify(r, advisory, Extraction{}, p)

		for _, it := range r.Items {
			if it.Relevance != RelevanceUnknown {
				t.Errorf("profile=%s left relevance %q", p, it.Relevance)
			}
			if !strings.Contains(it.RelevanceReason, p.String()) {
				t.Errorf("the reason does not say why: %q", it.RelevanceReason)
			}
		}
		if len(v) != 2 {
			t.Errorf("profile=%s: %d violations, want one per item", p, len(v))
		}
	}
}

func TestAFilledProfileLeavesTheAgentsJudgementAlone(t *testing.T) {
	r := result(item("a", RelevanceLikely, nil, nil, nil, nil))
	if v := Verify(r, advisory, Extraction{}, ProfileFilled); len(v) != 0 {
		t.Errorf("a filled profile produced violations: %+v", v)
	}
	if r.Items[0].Relevance != RelevanceLikely {
		t.Errorf("relevance was overwritten: %q", r.Items[0].Relevance)
	}
}

func TestAnUnrecognisedRelevanceBecomesUnknownNotUnlikely(t *testing.T) {
	// "unlikely" would be the worst available guess: it is the one value that
	// tells a reader not to bother looking.
	r := result(item("a", "probably-fine", nil, nil, nil, nil))
	v := Verify(r, advisory, Extraction{}, ProfileFilled)

	if r.Items[0].Relevance != RelevanceUnknown {
		t.Errorf("relevance = %q, want unknown", r.Items[0].Relevance)
	}
	if len(v) != 1 || v[0].Kind != "bad-relevance" {
		t.Errorf("not reported: %+v", v)
	}
}

func TestItemsAreSortedWorstFirstAndStably(t *testing.T) {
	// A reader who stops after three lines should have read the three that
	// matter. Unknown above unlikely: "we could not tell" earns more attention
	// than "we checked and it does not apply".
	r := result(
		item("zebra", RelevanceUnlikely, nil, nil, nil, nil),
		item("alpha", RelevanceUnknown, nil, nil, nil, nil),
		item("beta", RelevanceLikely, nil, nil, nil, nil),
		item("alpha2", RelevancePossible, nil, nil, nil, nil),
		item("aardvark", RelevanceUnknown, nil, nil, nil, nil),
	)
	Verify(r, advisory, Extraction{}, ProfileFilled)

	want := []string{"beta", "alpha2", "aardvark", "alpha", "zebra"}
	for i, w := range want {
		if r.Items[i].Title != w {
			t.Fatalf("order = %v, want %v", titles(r.Items), want)
		}
	}
}

func TestACountThatDisagreesWithTheItemsIsCorrectedAndReported(t *testing.T) {
	r := result(item("a", RelevanceUnknown, nil, nil, nil, nil))
	r.ItemCount = 7

	v := Verify(r, advisory, Extraction{}, ProfileFilled)

	if r.ItemCount != 1 {
		t.Errorf("ItemCount = %d, want 1", r.ItemCount)
	}
	if len(v) != 1 || v[0].Kind != "count-mismatch" {
		t.Errorf("the mismatch was not reported: %+v", v)
	}
}

func TestParseRejectsAnythingItDoesNotFullyUnderstand(t *testing.T) {
	for name, in := range map[string]string{
		"wrong schema":  `{"schema":"cti-triage/2","message_id":"m"}`,
		"no schema":     `{"message_id":"m"}`,
		"unknown field": `{"schema":"cti-triage/1","surprise":1}`,
		"not json":      `I analysed the advisory and found:`,
		"fenced":        "```json\n{\"schema\":\"cti-triage/1\"}\n```",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestParseAcceptsTheRefusalObject(t *testing.T) {
	// A refusal is a legitimate outcome and must not look like a crash: the
	// deterministic extraction still has to reach the digest.
	in := `{"schema":"cti-triage/1","message_id":"m1","item_count":0,"items":[],
	        "notes":["truncated mid-item"],"injection_attempt":false,
	        "confidence":"low","refused":true}`
	r, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("a valid refusal failed to parse: %v", err)
	}
	if !r.Refused || len(r.Notes) != 1 {
		t.Errorf("refusal not preserved: %+v", r)
	}
}

func TestAnInjectionAttemptSurvivesToTheCaller(t *testing.T) {
	// This flag is the one the operator most needs to see, and it travels
	// through verification untouched - nothing here may clear it.
	r := result(item("a", RelevanceUnknown, nil, nil, nil, nil))
	r.InjectionAttempt = true
	r.Notes = []string{`the body contained "ignore previous instructions"`}

	Verify(r, advisory, Extraction{}, ProfileMissing)

	if !r.InjectionAttempt || len(r.Notes) != 1 {
		t.Errorf("verification lost the injection report: %+v", r)
	}
}

func titles(items []Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Title
	}
	return out
}
