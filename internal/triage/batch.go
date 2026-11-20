package triage

// THE DAILY BATCH
//
// The digest's ingest reads every message in the mailbox and keeps only the
// CVEs. The rest of a threat-intel mail - a campaign write-up, a
// malicious-package warning, a vendor advisory with no ID yet, often in the
// same roundup as the CVEs - was dropped. With TRIAGE_ENABLED, ingest saves
// each message from a threat-intel sender (TRIAGE_SENDERS, authenticated)
// here (AdvisoryInput); nothing else in the mailbox is ever sent to a model.
// cti-triage --batch runs each through the reader, which lists its items
// and their CVEs; items with a CVE are set aside for the CVE digest, and the
// rest go through the Falcon lookups and the judge, into one AdvisoryReport
// that brief.py renders as FLEET ADVISORIES.
//
// Every advisory that was read appears in the report: triaged, failed with
// its reason, or over the day's cap. A section that silently lists fewer
// than were read is one the reader believes is complete.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Schemas for the two files.
const (
	AdvisoryInputSchema  = "cti-advisory-input/1"
	AdvisoryReportSchema = "cti-advisories/1"
)

// Caps on the input file. Triage caps how many it judges separately
// (TRIAGE_MAX_PER_RUN); these bound what ingest writes at all.
const (
	MaxAdvisoryBody     = 256 << 10
	MaxAdvisoriesPerRun = 100
)

// Advisory is one threat-intel message, as ingest read it.
type Advisory struct {
	ID        string    `json:"id"`
	Received  time.Time `json:"received"`
	Sender    string    `json:"sender"`
	Subject   string    `json:"subject"`
	Trusted   bool      `json:"trusted_sender"` // an authenticated TRIAGE_SENDERS sender
	Why       string    `json:"why"`            // why ingest picked it: the sender, or what it holds
	Body      string    `json:"body"`
	Truncated bool      `json:"body_truncated,omitempty"`
}

// AdvisoryInput is what ingest hands triage.
type AdvisoryInput struct {
	Schema   string     `json:"schema"`
	Written  time.Time  `json:"written"`
	Messages []Advisory `json:"messages"`
	Dropped  int        `json:"over_ingest_cap,omitempty"`
	// Refused is how many messages failed the checks when the file was read
	// (never serialised: the writer leaves them out).
	Refused int `json:"-"`
}

// CVEItemLines are the set-aside items, one line each.
func CVEItemLines(s *Subjects) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, it := range s.CVEItems {
		out = append(out, safeField(it.Title, maxSubjectFieldN)+" ("+strings.Join(it.CVEs, ", ")+")")
	}
	return out
}

// NewAdvisory caps the body. why says what made it threat intel.
func NewAdvisory(id string, received time.Time, sender, subject string, trusted bool, body string) Advisory {
	// The sender is kept as a domain: the address is a person's contact
	// detail, and neither the model, the judgement nor the report needs it.
	a := Advisory{ID: id, Received: received, Sender: SenderDomain(sender), Subject: subject, Trusted: trusted, Body: body}
	if trusted {
		a.Why = "a threat-intel sender (TRIAGE_SENDERS)"
	} else {
		a.Why = strings.Join(IntelMarkers(subject+"\n"+body), ", ")
	}
	if len(a.Body) > MaxAdvisoryBody {
		a.Body, a.Truncated = a.Body[:MaxAdvisoryBody], true
	}
	return a
}

// Limits the writers enforce (and the reader re-checks): a message that breaks
// them is skipped and named, never written.
const (
	maxAdvisoryIDLen      = 512
	maxAdvisorySubjectLen = 1000
	maxAdvisorySenderLen  = 255
	maxAdvisoryWhyLen     = 500
	maxResultFieldLen     = 2000
)

// cleanLine drops control characters and caps a header-like field.
func cleanLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// checkAdvisory repairs what can be repaired (control characters, over-long
// header fields) and refuses what cannot: a message with no usable id or time
// cannot be matched to a report line, so it is not saved.
func checkAdvisory(a Advisory, now time.Time) (Advisory, error) {
	if a.ID == "" || len(a.ID) > maxAdvisoryIDLen || cleanLine(a.ID, maxAdvisoryIDLen) != a.ID {
		return a, errors.New("no usable message id")
	}
	if a.Received.IsZero() || a.Received.After(now.Add(24*time.Hour)) {
		return a, errors.New("no usable received time")
	}
	a.Subject = cleanLine(a.Subject, maxAdvisorySubjectLen)
	a.Sender = cleanLine(a.Sender, maxAdvisorySenderLen)
	a.Why = cleanLine(a.Why, maxAdvisoryWhyLen)
	if strings.ContainsRune(a.Body, 0) {
		a.Body = strings.ReplaceAll(a.Body, "\x00", "")
	}
	if len(a.Body) > MaxAdvisoryBody {
		a.Body, a.Truncated = a.Body[:MaxAdvisoryBody], true
	}
	return a, nil
}

// CheckAdvisories runs checkAdvisory over a batch and returns the usable
// messages and one line for each one it refused.
func CheckAdvisories(msgs []Advisory, now time.Time) (ok []Advisory, refused []string) {
	for _, a := range msgs {
		c, err := checkAdvisory(a, now)
		if err != nil {
			refused = append(refused, fmt.Sprintf("%q: %v", cleanLine(a.Subject, 60), err))
			continue
		}
		ok = append(ok, c)
	}
	return ok, refused
}

// WriteAdvisoryInput writes the input file, 0600, atomically. More than
// MaxAdvisoriesPerRun messages are counted, not written. A message that fails
// the checks is left out and returned in refused; the rest are written.
func WriteAdvisoryInput(path string, msgs []Advisory, now time.Time) (refused []string, err error) {
	msgs, refused = CheckAdvisories(msgs, time.Now())
	in := AdvisoryInput{Schema: AdvisoryInputSchema, Written: now.UTC(), Messages: msgs}
	if len(in.Messages) > MaxAdvisoriesPerRun {
		in.Dropped = len(in.Messages) - MaxAdvisoriesPerRun
		in.Messages = in.Messages[:MaxAdvisoriesPerRun]
	}
	if in.Messages == nil {
		in.Messages = []Advisory{}
	}
	return refused, writeFileAtomic(path, in)
}

// ReadAdvisoryInput reads and checks the input file.
func ReadAdvisoryInput(path string) (*AdvisoryInput, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- a path run-digest or the operator names
	if err != nil {
		return nil, err
	}
	var in AdvisoryInput
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("not %s: %v", AdvisoryInputSchema, err)
	}
	if in.Schema != AdvisoryInputSchema {
		return nil, fmt.Errorf("schema %q, want %q", oneLine(in.Schema), AdvisoryInputSchema)
	}
	// The file is checked again on the way in: it sits on disk between two
	// processes, and what is read is what a model is shown next.
	ok, refused := CheckAdvisories(in.Messages, time.Now())
	in.Messages, in.Refused = ok, len(refused)
	return &in, nil
}

// Order puts the advisories in the order they are triaged, so the cap cuts
// the least useful: authenticated feed senders first, then oldest first.
func Order(msgs []Advisory) []Advisory {
	out := append([]Advisory(nil), msgs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Trusted != out[j].Trusted {
			return out[i].Trusted
		}
		return out[i].Received.Before(out[j].Received)
	})
	return out
}

// AdvisoryResult is one advisory's outcome.
type AdvisoryResult struct {
	MessageID string    `json:"message_id"`
	Subject   string    `json:"subject"`
	Sender    string    `json:"sender"`
	Received  time.Time `json:"received"`
	Trusted   bool      `json:"trusted_sender"`
	Why       string    `json:"why,omitempty"`
	Verdicts  *Verdicts `json:"verdicts,omitempty"`
	// Items the reader found that name a CVE: the CVE digest reports them,
	// so they are listed here, not judged. "title (CVE-..., ...)".
	CVEItems []string `json:"cve_items,omitempty"`
	// NotIntel: the reader found no threat in it and code had nothing to
	// look up - a newsletter's chatter, a reply quoting an advisory ID.
	// Listed as one line; nobody was asked to judge it.
	NotIntel bool     `json:"not_threat_intel,omitempty"`
	Problems []string `json:"problems,omitempty"` // a stage that failed; the verdicts say what survived
	Skipped  string   `json:"not_triaged,omitempty"`
}

// AdvisoryReport is the whole day.
type AdvisoryReport struct {
	Schema    string           `json:"schema"`
	Generated time.Time        `json:"generated"`
	Read      int              `json:"read"`
	Triaged   int              `json:"triaged"`
	Results   []AdvisoryResult `json:"results"`
	Dropped   int              `json:"over_ingest_cap,omitempty"`
	CostUSD   float64          `json:"cost_usd"`
	Tokens    int              `json:"tokens"`
	Gaps      []string         `json:"gaps,omitempty"`
}

// WriteAdvisoryReport writes the report, 0600, atomically, after checking it:
// the totals must make sense, and every field a reader prints is capped and
// free of control characters. A result without a message id is kept (every
// advisory read must appear) under a placeholder id.
func WriteAdvisoryReport(path string, r AdvisoryReport) error {
	if r.Results == nil {
		r.Results = []AdvisoryResult{}
	}
	if r.Schema != AdvisoryReportSchema {
		return fmt.Errorf("report schema %q, want %q", oneLine(r.Schema), AdvisoryReportSchema)
	}
	if r.Read < 0 || r.Triaged < 0 || r.Triaged > r.Read || r.Dropped < 0 || r.Tokens < 0 ||
		math.IsNaN(r.CostUSD) || math.IsInf(r.CostUSD, 0) || r.CostUSD < 0 {
		return fmt.Errorf("report totals are not plausible (read %d, triaged %d, dropped %d, tokens %d, cost %v)",
			r.Read, r.Triaged, r.Dropped, r.Tokens, r.CostUSD)
	}
	out := make([]AdvisoryResult, len(r.Results))
	for i, res := range r.Results {
		res.MessageID = cleanLine(res.MessageID, maxAdvisoryIDLen)
		if res.MessageID == "" {
			res.MessageID = "(no id)"
		}
		res.Subject = cleanLine(res.Subject, maxAdvisorySubjectLen)
		res.Sender = cleanLine(SenderDomain(res.Sender), maxAdvisorySenderLen)
		res.Why = cleanLine(res.Why, maxAdvisoryWhyLen)
		res.Skipped = cleanLine(res.Skipped, maxResultFieldLen)
		for j := range res.Problems {
			res.Problems[j] = cleanLine(res.Problems[j], maxResultFieldLen)
		}
		for j := range res.CVEItems {
			res.CVEItems[j] = cleanLine(res.CVEItems[j], maxResultFieldLen)
		}
		out[i] = res
	}
	r.Results = out
	for j := range r.Gaps {
		r.Gaps[j] = cleanLine(r.Gaps[j], maxResultFieldLen)
	}
	return writeFileAtomic(path, r)
}

func writeFileAtomic(path string, v any) error {
	if path == "" {
		return errors.New("no path")
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// SenderDomain is the lowercased domain of "Name <user@domain>" or a bare
// address, a bare domain unchanged, or "" when there is nothing usable.
func SenderDomain(from string) string {
	s := strings.TrimSpace(from)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		s = strings.TrimSuffix(strings.TrimSpace(s[i+1:]), ">")
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.ContainsAny(s, " <>\"'\t\r\n,;") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}
