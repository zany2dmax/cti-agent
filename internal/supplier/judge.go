package supplier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/zany2dmax/cti-agent/internal/redact"
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
	// NotRequest says the thread is not a request to set up a new supplier at
	// all: staff maintaining an existing vendor's record, a customer's credit
	// application, an internal question. It gets no Kanban item, and the digest
	// lists it as set aside so a person can still see what was left out. Like a
	// No it must clear every gate below, and it has one more: the thread has to
	// have been started by someone inside the company, so no supplier can
	// describe its own request out of review.
	NotRequest = "not_request"
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
	// InternalDomains are the mail domains of the company's own staff. A
	// NotRequest answer is accepted only for a thread that a sender at one of
	// these started. Empty means none is accepted.
	InternalDomains []string
	// HoldPhrases are word sequences that mark a thread as one that must never
	// be sent to the model (a customer's credit application, say: it is not a
	// supplier request and holds a stranger's financial and personal detail).
	// Nil means DefaultHoldPhrases; empty means none.
	HoldPhrases []string
}

// internalSender is true when the address is at one of the internal domains.
func (c Config) internalSender(addr string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return false
	}
	dom := addr[at+1:]
	for _, d := range c.InternalDomains {
		if d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "@"); d != "" && d == dom {
			return true
		}
	}
	return false
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
//
// ONLY WHAT THE QUESTION NEEDS. The model judges whether a supplier touches
// company data, systems or technology, so it is shown what kind of request
// this is, whether the spend is an expense or inventory, who the supplier is,
// and what the requester said about them. It is NOT shown the remittance
// address, the accounts-receivable contact, payment and credit terms, spend,
// the branch, the ERP, or the names of the requester and approver: none bears on
// the question, all are business or personal data, and the lane's own code (not
// the model) enforces the rules that use the sender and the form's structure.
// The full form still goes to the people who file and review the request.
// Every value is run through redact.Sensitive as well, because free text is
// where a tax id or an account number gets pasted.
func formLines(f Form) string {
	rows := []struct{ label, val string }{
		{"Request", f.Request},
		{"Expense or inventory", f.Class},
		{"Supplier name", f.Name},
		{"Additional notes", f.Notes},
	}
	var b strings.Builder
	for _, r := range rows {
		v := strings.TrimSpace(redact.Sensitive(r.val))
		if v == "" {
			v = "(blank)"
		}
		fmt.Fprintf(&b, "  %s: %s\n", r.label, v)
	}
	return b.String()
}

// senderDomain is what the model is told about the sender: the domain, never
// the person's address. Code has already decided whether the domain is
// internal; the model has no use for who wrote it.
func senderDomain(from string) string {
	s := strings.TrimSpace(from)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		s = strings.TrimSuffix(strings.TrimSpace(s[i+1:]), ">")
	}
	if at := strings.LastIndex(s, "@"); at >= 0 && at < len(s)-1 {
		return strings.ToLower(strings.TrimSpace(s[at+1:]))
	}
	return "(unknown)"
}

// Source is the untrusted text exactly as the model reads it. Evidence quotes
// are checked against this, so it is built once and used for both.
func (in Input) Source() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SENDER DOMAIN: %s\nSUBJECT: %s\n", defuse(senderDomain(in.Sender)), defuse(redact.Sensitive(in.Subject)))
	if in.State == StateRead && in.Form != nil {
		b.WriteString("FORM FIELDS:\n")
		b.WriteString(defuse(formLines(*in.Form)))
	}
	body := redact.Sensitive(in.Body)
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
// A No and a NotRequest need nobody.
func (d Decision) NeedsTPRM() bool { return d.Verdict != No && d.Verdict != NotRequest }

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
	return judge(raw, in, in.Source(), cfg)
}

// judge is Judge with the text the model read given explicitly, so a caller
// that stored it can check evidence against exactly that.
func judge(raw []byte, in Input, source string, cfg Config) Decision {
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
	case Yes, No, Unsure, NotRequest:
	default:
		return unsure("The judgement gave no usable answer, so this request needs a person.",
			fmt.Sprintf("verdict %q is not yes, no, unsure or not_request", r.Verdict))
	}

	// Evidence must be copied from the request, not composed.
	src := squash(source)
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
	if d.Verdict != No && d.Verdict != NotRequest {
		return d
	}

	// From here only a No or a NotRequest is being checked, and each must clear
	// every gate.
	what := "a No"
	if d.Verdict == NotRequest {
		what = "something other than a new supplier request"
	}
	gate := func(note string) Decision {
		d.Notes = append(d.Notes, note)
		d.Verdict = Unsure
		d.Reason = "Could not be shown to be " + what + ". " + d.Reason
		return d
	}
	if r.InjectionAttempt {
		return gate("a No is not accepted when the request tries to steer the reader")
	}
	if d.Verdict == NotRequest {
		// A supplier form, attached or linked, is a request to set one up.
		switch {
		case in.State != StateNone:
			return gate("a supplier form came with this thread, so it is treated as a request")
		case !cfg.internalSender(in.Sender):
			return gate("the thread was not started by a sender at an internal domain")
		}
	} else {
		switch in.State {
		case StateLinked:
			return gate("form not readable: linked, not attached")
		case StateUnreadable:
			return gate("form not readable: the attachment is not a supplier form")
		}
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

// ─── threads that never reach the model ─────────────────────────────────────

// DefaultHoldPhrases mark a thread as a customer's credit application or the
// like. Matched as whole-word sequences, case-insensitively, in the subject,
// the message text and the form's name and notes.
var DefaultHoldPhrases = []string{
	"credit application", "credit app", "application for credit", "customer credit",
	"personal guarantee", "personal guaranty", "guarantor",
}

func (c Config) holdPhrases() []string {
	if c.HoldPhrases != nil {
		return c.HoldPhrases
	}
	return DefaultHoldPhrases
}

func holdWords(s string) []string {
	// Invisible format characters (zero-width space and the like) are removed
	// first, as the redactor does, so "cre<ZWSP>dit application" is still a
	// credit application.
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// HoldPhrase returns the first phrase that marks the request as one the model
// must not see, or "".
//
// WHY CODE DECIDES. The agent instructions let the model call a customer's
// credit application "not a request"; to say so it had to read the application
// first, with a stranger's name, address, bank and trade references in it. The
// redaction catches account and tax numbers, not who someone is. A thread that
// plainly is one is recognised here, before anything is sent, and goes to a
// person as an Unsure (HeldDecision): the model never receives it.
func (c Config) HoldPhrase(in Input) string {
	text := in.Subject + "\n" + in.Body
	if in.Form != nil {
		text += "\n" + in.Form.Name + "\n" + in.Form.Notes
	}
	w := holdWords(text)
	for _, p := range c.holdPhrases() {
		pw := holdWords(p)
		if len(pw) == 0 {
			continue
		}
	scan:
		for i := 0; i+len(pw) <= len(w); i++ {
			for j := range pw {
				if w[i+j] != pw[j] {
					continue scan
				}
			}
			return strings.Join(pw, " ")
		}
	}
	return ""
}

// HeldDecision is the verdict for a thread that was held from the model: always
// Unsure, so a person looks at it. Never a No and never a NotRequest, whatever
// the thread says: "credit application" is a customer applying to us, or us
// applying to a new supplier (which IS a supplier request), and code cannot
// tell which without reading what the model must not see. An Unsure costs a
// person a look; a wrong dismissal costs a missed supplier review.
func HeldDecision(phrase string) Decision {
	return Decision{
		Verdict: Unsure,
		Reason: "This looks like a credit application, so it was not sent to the AI. " +
			"It may be a customer's (not a supplier request) or ours to a new supplier (which is one); a person needs to look.",
		Notes: []string{fmt.Sprintf("held from the AI: the thread contains %q; no model judged it", phrase)},
	}
}
