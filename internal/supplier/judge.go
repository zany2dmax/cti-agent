package supplier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// This file is the judgement half of the supplier-request lane: what the model
// is shown, what it may answer, and the checks code applies to the answer
// before anyone sees it. It follows the pattern in internal/triage: the model
// has no tools, reads one block of hostile text, writes one JSON object, and
// code - not the model - enforces every promise made in its instructions.
//
// THE QUESTION. Will this supplier have access to company data, systems or
// networks, or provide technology (hardware, software, connected equipment)?
// A Yes means the supplier is critical and has to go through third-party risk
// management. A No means a supplier of materials or other non-technology goods.
//
// THE ASYMMETRY. A wrong Yes costs somebody a look. A wrong No lets a critical
// supplier in unreviewed. So the only answer the model can give that code
// trusts without checking is "unsure", and a "no" survives only if every
// check below passes. Anything that cannot be shown to be a No is Unsure, and
// an Unsure gets the same Kanban to-do as a Yes.

// Schema is the only output shape code will parse.
const Schema = "cti-supplier/1"

// Verdicts. Unsure is the default for everything that is not shown.
const (
	Yes    = "yes"
	No     = "no"
	Unsure = "unsure"
)

// FormState says what the lane found for a request's form, which limits what
// a No can rest on.
type FormState string

const (
	// StateRead: a form was attached and read.
	StateRead FormState = "read"
	// StateNone: no form was attached and none was linked (the request is judged
	// from the message text alone).
	StateNone FormState = "none"
	// StateLinked: the form arrived as a link in the body, which the lane does not open.
	StateLinked FormState = "linked"
	// StateUnreadable: a form was attached but could not be read as one.
	StateUnreadable FormState = "unreadable"
)

// Config is the operator's wording and word list, from fleet.env. The defaults
// are generic: no organisation, address or supplier is named in this repo.
type Config struct {
	// Question is the question as the organisation asks it.
	Question string
	// Critical says what a Yes means, in the organisation's words.
	Critical string
	// TechTerms are words which, found in the supplier name, subject or the
	// form's notes, stop a No from standing. Nil means DefaultTechTerms.
	TechTerms []string
	// TPRM names the process a critical supplier goes through, in the
	// organisation's words. Empty means a generic phrase.
	TPRM string
	// UnsureText is what the Jira item says when the answer is Unsure. Empty
	// means a generic sentence. It is operator text, not model output.
	UnsureText string
}

func (c Config) tprm() string {
	if strings.TrimSpace(c.TPRM) != "" {
		return strings.TrimSpace(c.TPRM)
	}
	return "third-party risk management process"
}

func (c Config) unsureText(board string) string {
	if strings.TrimSpace(c.UnsureText) != "" {
		return strings.TrimSpace(c.UnsureText)
	}
	if board == "" {
		board = "security team's"
	}
	return "We could not determine a 100% Yes, so this is Unsure, and an Unsure gets a to-do on the " + board + " Kanban board."
}

// DefaultTechTerms are whole words that suggest a technology supplier.
var DefaultTechTerms = []string{
	"software", "saas", "cloud", "cyber", "network", "networks", "networking",
	"hosting", "telecom", "telecommunications", "wireless", "server", "servers",
	"iot", "hardware", "computer", "computers", "technology", "technologies",
	"tech", "data", "digital", "systems", "internet", "app", "platform",
}

func (c Config) question() string {
	if strings.TrimSpace(c.Question) != "" {
		return strings.TrimSpace(c.Question)
	}
	return "Will this supplier have access to company data, systems or networks, or provide technology?"
}

func (c Config) critical() string {
	if strings.TrimSpace(c.Critical) != "" {
		return strings.TrimSpace(c.Critical)
	}
	return "A Yes means the supplier is critical: it touches company data, systems or networks, or provides " +
		"technology (hardware, software or connected equipment). A No means a supplier of materials or other " +
		"non-technology goods and services. If you cannot tell, the answer is unsure."
}

func (c Config) terms() []string {
	if c.TechTerms == nil {
		return DefaultTechTerms
	}
	return c.TechTerms
}

// Input is one request as the model sees it.
type Input struct {
	MessageID string
	Received  string
	Sender    string
	Subject   string
	Body      string
	State     FormState
	// Form is set when State is StateRead.
	Form *Form
}

// maxBody bounds the message text handed to the model.
const maxBody = 20000

const (
	beginMark = "<<<BEGIN UNTRUSTED CONTENT"
	endMark   = "END UNTRUSTED CONTENT>>>"
)

// defuse removes the block markers from hostile text so it cannot close the
// block early and pass its own words off as instructions.
func defuse(s string) string {
	s = strings.ReplaceAll(s, beginMark, "[marker removed]")
	return strings.ReplaceAll(s, endMark, "[marker removed]")
}

// formLines renders the form's answers for the model, blanks marked as blank.
func formLines(f Form) string {
	rows := []struct{ label, val string }{
		{"Request", f.Request}, {"Branch/market", f.Branch}, {"ERP", f.ERP},
		{"Expense or inventory", f.Class}, {"Supplier name", f.Name},
		{"Remittance address", f.Address}, {"Accounts receivable contact", f.ARContact},
		{"Payment terms", f.PaymentTerms}, {"Anticipated monthly spend", f.MonthlySpend},
		{"Credit limit", f.CreditLimit}, {"PO required", f.PORequired},
		{"Requested by", f.RequestedBy}, {"Approved by", f.ApprovedBy},
		{"Additional notes", f.Notes},
	}
	var b strings.Builder
	for _, r := range rows {
		v := strings.TrimSpace(r.val)
		if v == "" {
			v = "(blank)"
		}
		fmt.Fprintf(&b, "  %s: %s\n", r.label, v)
	}
	return b.String()
}

// Source is the untrusted text exactly as the model reads it. Evidence quotes
// are checked against this, so it is built once and used for both.
func (in Input) Source() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SENDER: %s\nSUBJECT: %s\n", defuse(in.Sender), defuse(in.Subject))
	if in.State == StateRead && in.Form != nil {
		b.WriteString("FORM FIELDS:\n")
		b.WriteString(defuse(formLines(*in.Form)))
	}
	body := in.Body
	truncated := false
	if len(body) > maxBody {
		body, truncated = body[:maxBody], true
	}
	b.WriteString("MESSAGE TEXT:\n")
	b.WriteString(defuse(body))
	if truncated {
		b.WriteString("\n[message text cut here]")
	}
	return b.String()
}

// Render builds the file handed to the model: the operator's wording and the
// facts code established outside the block, the request inside it.
func Render(in Input, cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MESSAGE-ID: %s\nRECEIVED:   %s\n", in.MessageID, in.Received)
	fmt.Fprintf(&b, "QUESTION:   %s\n", cfg.question())
	fmt.Fprintf(&b, "MEANING:    %s\n", cfg.critical())
	fmt.Fprintf(&b, "FORM:       %s\n\n", in.State)
	b.WriteString(beginMark + "\n")
	b.WriteString(in.Source())
	b.WriteString("\n" + endMark + "\n")
	return b.String()
}

// Result is the model's JSON object.
type Result struct {
	Schema           string   `json:"schema"`
	MessageID        string   `json:"message_id"`
	Verdict          string   `json:"verdict"`
	Reason           string   `json:"reason"`
	Evidence         []string `json:"evidence"`
	Notes            []string `json:"notes"`
	InjectionAttempt bool     `json:"injection_attempt"`
	Refused          bool     `json:"refused"`
}

// ParseResult decodes the model's output, strictly: an unknown field means a
// shape this code no longer understands.
func ParseResult(b []byte) (*Result, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Result
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("supplier judgement is not the expected JSON: %w", err)
	}
	if r.Schema != Schema {
		return nil, fmt.Errorf("supplier judgement has schema %q, want %q", r.Schema, Schema)
	}
	return &r, nil
}

// Decision is what the lane acts on: the model's answer after code has checked
// it. It is never more certain than the evidence allows.
type Decision struct {
	Verdict string
	Reason  string
	// Evidence holds only quotes confirmed to be in the request.
	Evidence []string
	// Notes explains every way code changed or distrusted the model's answer, so
	// the person reading the Kanban item can see why an Unsure is one.
	Notes []string
	// InjectionAttempt is true when the model reported text aimed at an AI reader.
	InjectionAttempt bool
}

// NeedsTPRM is true for Yes and for Unsure: an Unsure is treated as critical.
func (d Decision) NeedsTPRM() bool { return d.Verdict != No }

// squash collapses all whitespace, so a quote that spans a line break still
// matches the text it came from.
func squash(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func unsure(reason string, notes ...string) Decision {
	return Decision{Verdict: Unsure, Reason: reason, Notes: notes}
}

// techTermIn returns the first whole word of text that is in terms.
func techTermIn(text string, terms []string) string {
	if len(terms) == 0 {
		return ""
	}
	set := map[string]bool{}
	for _, t := range terms {
		set[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if set[w] {
			return w
		}
	}
	return ""
}

// Judge turns the model's raw output into a Decision. It never returns an error:
// output code cannot use is itself an answer, and the answer is Unsure with the
// reason. Every rule below can only move a verdict toward Unsure.
func Judge(raw []byte, in Input, cfg Config) Decision {
	r, err := ParseResult(raw)
	if err != nil {
		return unsure("The judgement could not be read, so this request needs a person.", err.Error())
	}
	if r.Refused {
		return unsure("The model declined to judge this request, so it needs a person.", "model refused")
	}
	if r.MessageID != in.MessageID {
		return unsure("The judgement named a different message, so it was not used.",
			fmt.Sprintf("message_id %q does not match %q", r.MessageID, in.MessageID))
	}

	d := Decision{Verdict: r.Verdict, Reason: strings.TrimSpace(r.Reason), InjectionAttempt: r.InjectionAttempt}
	if r.InjectionAttempt {
		d.Notes = append(d.Notes, "the request contains text aimed at an AI reader")
	}
	switch d.Verdict {
	case Yes, No, Unsure:
	default:
		return unsure("The judgement gave no usable answer, so this request needs a person.",
			fmt.Sprintf("verdict %q is not yes, no or unsure", r.Verdict))
	}

	// Evidence must be copied from the request, not composed.
	src := squash(in.Source())
	for _, q := range r.Evidence {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		if strings.Contains(src, squash(q)) {
			d.Evidence = append(d.Evidence, q)
		} else {
			d.Notes = append(d.Notes, fmt.Sprintf("a quoted line is not in the request and was dropped: %q", q))
		}
	}

	if d.Verdict != Unsure && len(d.Evidence) == 0 {
		d.Notes = append(d.Notes, "no quoted line from the request supports the "+d.Verdict)
		d.Verdict = Unsure
		d.Reason = "Not enough shown to be sure (" + strings.ToLower(r.Verdict) + " had no supporting quote). " + d.Reason
		return d
	}
	if d.Verdict != No {
		return d
	}

	// From here only a No is being checked, and a No must clear every gate.
	gate := func(note string) Decision {
		d.Notes = append(d.Notes, note)
		d.Verdict = Unsure
		d.Reason = "Could not be shown to be a No. " + d.Reason
		return d
	}
	if r.InjectionAttempt {
		return gate("a No is not accepted when the request tries to steer the reader")
	}
	switch in.State {
	case StateLinked:
		return gate("form not readable: linked, not attached")
	case StateUnreadable:
		return gate("form not readable: the attachment is not a supplier form")
	}
	var named string
	if in.Form != nil {
		named = in.Form.Name + " " + in.Form.Notes
	}
	if w := techTermIn(in.Subject+" "+named, cfg.terms()); w != "" {
		return gate(fmt.Sprintf("the name, subject or notes contain %q, a technology word", w))
	}
	return d
}
