package triage

// THE JUDGE: WHETHER AN ADVISORY IS WORTH SOMEONE'S TIME
//
// The second of two models (the triage redesign plan, Phase 4). It sees the
// fact sheet code gathered - what our own tools say - and the reader's
// checked subjects, never the advisory itself, and it has no tools. It says,
// per subject, likely / possible / unlikely / unknown, and why, citing the
// facts it relied on by their IDs.
//
// Code does not take its word for anything either. VerifyJudgement:
//
//   - drops a cited fact ID that does not exist or belongs to another
//     subject;
//   - downgrades "likely" with no cited strong fact (one of our hosts saw an
//     indicator, or runs the product) to "possible";
//   - removes a reason that says "affected" / "not affected" / "safe" about
//     us, or claims a sighting or an installation it did not cite a fact
//     for, and puts the cited facts in its place;
//   - raises any subject to at least "possible" when code knows better: the
//     product is installed and not known to be fixed, or one of our hosts saw
//     one of the advisory's indicators;
//   - turns "unlikely" into "unknown" when the inventory lookup for that
//     subject failed or was skipped, because "we could not look" is not
//     "we looked and it is not there";
//   - judges a subject the model skipped as "unknown", never leaves it out.
//
// Indicator sightings are reported by code on their own (Sightings), whatever
// the judge says and even when it never answers: a model must never be able
// to hide that one of our hosts talked to an attacker's domain.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// JudgementSchema is the only judge output this code parses.
const JudgementSchema = "cti-judgement/1"

// VerdictsSchema names what cti-triage --judge prints as JSON: the checked
// judgement, the sightings and the gaps, built by code.
const VerdictsSchema = "cti-verdicts/1"

const (
	maxReasonRunes = 400
	maxChecks      = 3
	maxCheckRunes  = 200
)

// Fact kinds. Strong facts are the only ones that can carry "likely".
const (
	FactInventory = "inventory" // an installed application matching a subject
	FactAbsent    = "absent"    // looked up, not found
	FactSighting  = "sighting"  // one of our hosts saw an indicator
	FactAlerts    = "alerts"    // Falcon alerts on a technique, last 30 days
	FactGap       = "gap"       // what could not be looked up or is not visible
)

// Fact is one line of the judge's input, with the ID it cites it by.
type Fact struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Subject string `json:"subject,omitempty"` // "S1"..; "" = the advisory as a whole
	Text    string `json:"text"`
	Hosts   int    `json:"hosts,omitempty"`

	// For inventory facts: hosts below the fixed version, nil when unknown.
	BelowFixed *int `json:"hosts_below_fixed,omitempty"`
}

// Strong reports whether the fact is about our own hosts having the thing.
func (f Fact) Strong() bool {
	return (f.Kind == FactInventory || f.Kind == FactSighting) && f.Hosts > 0
}

// SubjectRef is one subject as the judge is shown it.
type SubjectRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Name  string `json:"name"`
}

// JudgeInput is everything the judge is shown, as code built it.
type JudgeInput struct {
	Subjects []SubjectRef
	Facts    []Fact
	Text     string
}

// BuildJudgeInput turns a fact sheet into the judge's input. When the reader
// named no subjects, the advisory as a whole is the one subject (S1), so
// there is always something to judge and its sightings and techniques still
// count.
func BuildJudgeInput(m Message, sheet FactSheet) JudgeInput {
	var in JudgeInput
	add := func(kind, subject, text string, hosts int, below *int) {
		in.Facts = append(in.Facts, Fact{ID: fmt.Sprintf("F%d", len(in.Facts)+1), Kind: kind,
			Subject: subject, Text: text, Hosts: hosts, BelowFixed: below})
	}
	q := func(s string) string { return fmt.Sprintf("%q", safeField(s, 80)) }

	for i, sf := range sheet.Subjects {
		id := fmt.Sprintf("S%d", i+1)
		name := sf.Product
		if sf.Vendor != "" && name != "" {
			name = sf.Vendor + " / " + name
		}
		in.Subjects = append(in.Subjects, SubjectRef{ID: id, Title: safeField(sf.Title, maxSubjectFieldN), Name: safeField(name, maxSubjectFieldN)})
		switch {
		case sf.Error != "":
			add(FactGap, id, "the inventory lookup failed, so whether we run it is unknown", 0, nil)
		case sf.Skipped != "":
			add(FactGap, id, "not looked up in the inventory: "+safeField(sf.Skipped, 120), 0, nil)
		case len(sf.Apps) == 0:
			add(FactAbsent, id, "no matching application on any host Falcon sees", 0, nil)
		}
		for _, a := range sf.Apps {
			t := fmt.Sprintf("installed: %s / %s on %d host(s)", q(a.Vendor), q(a.Name), a.Hosts)
			if sf.Vendor != "" && !a.VendorMatches {
				t += ", vendor differs from the advisory's"
			}
			if a.BelowFixed != nil {
				t += fmt.Sprintf("; about %d host(s) below the fixed version %s", *a.BelowFixed, q(sf.FixedIn))
				if a.UncomparedHosts > 0 {
					t += fmt.Sprintf(", %d on versions that cannot be compared", a.UncomparedHosts)
				}
			} else {
				t += "; no fixed version given, so versions are not compared"
			}
			if a.Exposure["internet"] > 0 {
				t += fmt.Sprintf("; %d internet-facing", a.Exposure["internet"])
			}
			if a.SuspiciousHosts > 0 {
				t += fmt.Sprintf("; Falcon flags it as suspicious on %d host(s)", a.SuspiciousHosts)
			}
			if sf.Truncated {
				t += " (counts are lower bounds)"
			}
			add(FactInventory, id, t, a.Hosts, a.BelowFixed)
		}
	}
	if len(in.Subjects) == 0 {
		title := "the advisory as a whole"
		if strings.TrimSpace(m.Subject) != "" {
			title = safeField(m.Subject, maxSubjectFieldN)
		}
		in.Subjects = append(in.Subjects, SubjectRef{ID: "S1", Title: title})
	}

	notSeen, failed := 0, 0
	for _, i := range sheet.Indicators {
		switch {
		case i.Error != "":
			failed++
		case i.Skipped != "":
		case i.Hosts > 0:
			add(FactSighting, "", fmt.Sprintf("indicator %s (%s) was seen on %d of our host(s)", q(i.Value), i.Type, i.Hosts), i.Hosts, nil)
		default:
			notSeen++
		}
	}
	if notSeen > 0 {
		add(FactAbsent, "", fmt.Sprintf("%d of the advisory's indicators were looked up and not seen on any host", notSeen), 0, nil)
	}
	if failed > 0 {
		add(FactGap, "", fmt.Sprintf("%d indicator lookup(s) failed", failed), 0, nil)
	}
	for _, t := range sheet.Techniques {
		by := "named by the advisory"
		if t.Source == "reader" {
			by = "inferred by the reader"
		}
		switch {
		case t.Error != "":
			add(FactGap, "", fmt.Sprintf("the alert lookup for %s failed", t.ID), 0, nil)
		case t.Skipped != "":
		case t.Alerts > 0:
			add(FactAlerts, "", fmt.Sprintf("%s (%s): %d Falcon alert(s) in the last 30 days", t.ID, by, t.Alerts), 0, nil)
		default:
			add(FactAbsent, "", fmt.Sprintf("%s (%s): no Falcon alerts in the last 30 days", t.ID, by), 0, nil)
		}
	}
	for _, g := range Gaps(sheet) {
		add(FactGap, "", g, 0, nil)
	}
	in.Text = renderJudgeInput(m, in)
	return in
}

// Gaps is what the sheet cannot see, said by code on every result.
func Gaps(sheet FactSheet) []string {
	var g []string
	if sheet.BlindSpots != "" {
		g = append(g, "not visible to Falcon: "+safeField(sheet.BlindSpots, 200))
	} else {
		g = append(g, "anything without the Falcon sensor is not covered")
	}
	if sheet.Sensors > 0 {
		g = append(g, fmt.Sprintf("Falcon has seen %d hosts in the last 30 days", sheet.Sensors))
	}
	if sheet.Refused != "" {
		g = append(g, "the reader refused this advisory, so no products were looked up")
	}
	return g
}

func renderJudgeInput(m Message, in JudgeInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MESSAGE-ID: %s\n", oneLine(m.ID))
	b.WriteString("\nFACTS (from our own tools, gathered by code)\n")
	for _, f := range in.Facts {
		who := "advisory"
		if f.Subject != "" {
			who = f.Subject
		}
		fmt.Fprintf(&b, "%s [%s, %s] %s\n", f.ID, f.Kind, who, f.Text)
	}
	b.WriteString("\n" + BeginContent + " (the reader's subjects: words from the advisory)\n")
	for _, s := range in.Subjects {
		fmt.Fprintf(&b, "%s title=%q name=%q\n", s.ID, s.Title, s.Name)
	}
	b.WriteString(EndContent + "\n")
	return b.String()
}

// safeField makes text from the advisory, the reader or an API safe to
// place in the judge's input: one line, no fence markers, capped.
func safeField(s string, max int) string {
	s = oneLine(stripMarkers(s))
	r := []rune(s)
	if len(r) > max {
		s = string(r[:max]) + "..."
	}
	return s
}

// ─── the judge's answer ─────────────────────────────────────────────────────

// Judged is the judge's view of one subject.
type Judged struct {
	Subject   string   `json:"subject"`
	Relevance string   `json:"relevance"`
	Reason    string   `json:"reason"`
	Facts     []string `json:"facts"`
	Checks    []string `json:"checks"`
}

// Judgement is the judge's whole answer.
type Judgement struct {
	Schema  string   `json:"schema"`
	Items   []Judged `json:"items"`
	Refusal *struct {
		Reason string `json:"reason"`
	} `json:"refusal"`
}

// ParseJudgement reads the judge's answer, strictly: the outermost JSON
// object, no unknown fields, the right schema.
func ParseJudgement(b []byte) (*Judgement, error) {
	s := strings.TrimSpace(string(b))
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i < 0 || j <= i {
		return nil, errors.New("judge: no JSON object in the answer")
	}
	var out Judgement
	dec := json.NewDecoder(strings.NewReader(s[i : j+1]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("judge: answer is not %s: %v", JudgementSchema, err)
	}
	if out.Schema != JudgementSchema {
		return nil, fmt.Errorf("judge: schema %q, want %q", oneLine(out.Schema), JudgementSchema)
	}
	return &out, nil
}

// ─── checked verdicts ───────────────────────────────────────────────────────

// Verdict is one subject's checked judgement.
type Verdict struct {
	Subject   string   `json:"subject"`
	Title     string   `json:"title"`
	Name      string   `json:"name,omitempty"`
	Relevance string   `json:"relevance"`
	Reason    string   `json:"reason"`
	ReasonBy  string   `json:"reason_by"` // "judge" or "code"
	Facts     []Fact   `json:"facts"`
	Checks    []string `json:"suggested_checks,omitempty"`
	RaisedBy  string   `json:"raised_by_code,omitempty"` // why code overrode the judge's relevance
}

// Verdicts is the whole checked result for one advisory.
type Verdicts struct {
	Schema    string          `json:"schema"`
	MessageID string          `json:"message_id"`
	Sightings []IndicatorFact `json:"sightings"`
	Gaps      []string        `json:"gaps"`
	Verdicts  []Verdict       `json:"verdicts"`
	JudgeDown string          `json:"judge_unavailable,omitempty"`
	Removed   []string        `json:"judge_claims_removed,omitempty"`
}

// Sightings is every indicator one of our hosts saw. Code only.
func Sightings(sheet FactSheet) []IndicatorFact {
	out := []IndicatorFact{}
	for _, i := range sheet.Indicators {
		if i.Error == "" && i.Skipped == "" && i.Hosts > 0 {
			out = append(out, i)
		}
	}
	return out
}

var (
	// Statements about us that only a person who has checked may make.
	verdictWordRE = regexp.MustCompile(`(?i)\b(un)?affected\b|\bnot\s+vulnerable\b|\b(we\s+are|we're|we\s+were|we\s+aren't|we\s+are\s+not)\s+(safe|vulnerable|compromised|protected|fine|exposed)\b|\bno\s+(risk|exposure|impact)\b`)
	// "Affected versions" describes the product, not us.
	affectedVersionsRE = regexp.MustCompile(`(?i)\baffected\s+(versions?|builds?|releases?|products?|range)\b`)
	// A claim that our hosts saw something ("seen in the wild" is not one).
	sightingClaimRE = regexp.MustCompile(`(?i)\b(seen|observed|sighted)\s+on\b|\bour\s+hosts?\s+(saw|contacted|reached|connected)\b|\bbeacon\w*`)
	installClaimRE  = regexp.MustCompile(`(?i)\b(we\s+run|we\s+use|installed|deployed|in\s+use|present\s+on|running\s+on)\b`)
)

// VerifyJudgement checks the judge's answer against the input it was shown.
// j may be nil (the judge failed or was not run): every subject is then
// judged by code alone, as unknown unless code knows better, and down says
// why.
func VerifyJudgement(j *Judgement, in JudgeInput, sheet FactSheet, messageID, down string) Verdicts {
	out := Verdicts{Schema: VerdictsSchema, MessageID: messageID, Sightings: Sightings(sheet), Gaps: Gaps(sheet), JudgeDown: down}
	removed := func(format string, a ...any) { out.Removed = append(out.Removed, fmt.Sprintf(format, a...)) }

	facts := map[string]Fact{}
	for _, f := range in.Facts {
		facts[f.ID] = f
	}
	byID := map[string]Judged{}
	if j != nil && j.Refusal != nil {
		if out.JudgeDown == "" {
			out.JudgeDown = "the judge refused: " + safeField(j.Refusal.Reason, 200)
		}
	} else if j != nil {
		known := map[string]bool{}
		for _, s := range in.Subjects {
			known[s.ID] = true
		}
		for _, it := range j.Items {
			id := strings.ToUpper(strings.TrimSpace(it.Subject))
			switch {
			case !known[id]:
				removed("a judgement for %q, which is not a subject", safeField(it.Subject, 20))
			case byID[id].Subject != "":
				removed("%s: a second judgement, ignored", id)
			default:
				it.Subject = id
				byID[id] = it
			}
		}
	}

	sighted := len(out.Sightings) > 0
	for _, s := range in.Subjects {
		v := Verdict{Subject: s.ID, Title: s.Title, Name: s.Name, Relevance: RelevanceUnknown, ReasonBy: "code", Facts: []Fact{}}
		it, judged := byID[s.ID]
		if !judged {
			v.Reason = "no judgement from the judge"
			if out.JudgeDown == "" && j != nil {
				removed("%s: the judge gave no judgement; judged unknown", s.ID)
			}
		} else {
			v.ReasonBy, v.Reason = "judge", safeField(it.Reason, maxReasonRunes)
			switch it.Relevance {
			case RelevanceLikely, RelevancePossible, RelevanceUnlikely, RelevanceUnknown:
				v.Relevance = it.Relevance
			default:
				removed("%s: relevance %q is not likely/possible/unlikely/unknown; judged unknown", s.ID, safeField(it.Relevance, 20))
			}
			seen := map[string]bool{}
			for _, id := range it.Facts {
				id = strings.ToUpper(strings.TrimSpace(id))
				f, ok := facts[id]
				switch {
				case seen[id]:
				case !ok:
					removed("%s: cited %q, which is not a fact", s.ID, safeField(id, 20))
				case f.Subject != "" && f.Subject != s.ID:
					removed("%s: cited %s, a fact about %s", s.ID, id, f.Subject)
				default:
					v.Facts = append(v.Facts, f)
				}
				seen[id] = true
			}
			for _, c := range it.Checks {
				if len(v.Checks) == maxChecks {
					break
				}
				if c = safeField(c, maxCheckRunes); c != "" {
					v.Checks = append(v.Checks, c)
				}
			}
			// A claim about sightings needs a cited indicator fact, seen or
			// not; a claim about what we run needs a cited inventory fact
			// for this subject, found or not.
			var strong, indicatorCited, inventoryCited bool
			for _, f := range v.Facts {
				strong = strong || f.Strong()
				indicatorCited = indicatorCited || f.Kind == FactSighting || (f.Kind == FactAbsent && f.Subject == "" && strings.Contains(f.Text, "indicator"))
				inventoryCited = inventoryCited || ((f.Kind == FactInventory || f.Kind == FactAbsent) && f.Subject == s.ID)
			}
			if v.Relevance == RelevanceLikely && !strong {
				removed("%s: likely, citing no host that has the product or saw an indicator; now possible", s.ID)
				v.Relevance = RelevancePossible
			}
			bad := ""
			reason := affectedVersionsRE.ReplaceAllString(v.Reason, "")
			switch {
			case verdictWordRE.MatchString(reason):
				bad = "said whether we are affected, which only a person who has checked may say"
			case sightingClaimRE.MatchString(reason) && !indicatorCited:
				bad = "claimed a sighting without citing one"
			case installClaimRE.MatchString(reason) && !inventoryCited:
				bad = "claimed the product is installed without citing an inventory fact"
			}
			if bad != "" {
				removed("%s: reason removed: it %s", s.ID, bad)
				v.ReasonBy, v.Reason = "code", "the judge's reason was removed (it "+bad+"); see the facts"
			}
		}
		raise(&v, in.Facts, sighted)
		out.Verdicts = append(out.Verdicts, v)
	}
	sortVerdicts(out.Verdicts)
	return out
}

// raise applies what code knows, whatever the judge said.
func raise(v *Verdict, facts []Fact, sighted bool) {
	var installed, gap bool
	var why string
	for _, f := range facts {
		if f.Subject != v.Subject {
			continue
		}
		switch f.Kind {
		case FactInventory:
			if f.Hosts > 0 && (f.BelowFixed == nil || *f.BelowFixed > 0) {
				installed, why = true, f.ID+": the product is installed and not known to be fixed"
				addFact(v, f)
			}
		case FactGap:
			gap = true
			addFact(v, f)
		}
	}
	if sighted && why == "" {
		why = "one of our hosts saw one of the advisory's indicators"
		for _, f := range facts {
			if f.Kind == FactSighting {
				addFact(v, f)
			}
		}
	}
	if (installed || sighted) && rank(v.Relevance) > rank(RelevancePossible) {
		v.Relevance, v.RaisedBy = RelevancePossible, why
		return
	}
	if gap && v.Relevance == RelevanceUnlikely {
		v.Relevance, v.RaisedBy = RelevanceUnknown, "the inventory lookup for it failed or was skipped, so unlikely cannot be shown"
	}
}

func addFact(v *Verdict, f Fact) {
	for _, g := range v.Facts {
		if g.ID == f.ID {
			return
		}
	}
	v.Facts = append(v.Facts, f)
}

func sortVerdicts(vs []Verdict) {
	for i := 1; i < len(vs); i++ {
		for k := i; k > 0 && rank(vs[k].Relevance) < rank(vs[k-1].Relevance); k-- {
			vs[k], vs[k-1] = vs[k-1], vs[k]
		}
	}
}
