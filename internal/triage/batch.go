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
	a := Advisory{ID: id, Received: received, Sender: sender, Subject: subject, Trusted: trusted, Body: body}
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

// WriteAdvisoryInput writes the input file, 0600, atomically. More than
// MaxAdvisoriesPerRun messages are counted, not written.
func WriteAdvisoryInput(path string, msgs []Advisory, now time.Time) error {
	in := AdvisoryInput{Schema: AdvisoryInputSchema, Written: now.UTC(), Messages: msgs}
	if len(in.Messages) > MaxAdvisoriesPerRun {
		in.Dropped = len(in.Messages) - MaxAdvisoriesPerRun
		in.Messages = in.Messages[:MaxAdvisoriesPerRun]
	}
	if in.Messages == nil {
		in.Messages = []Advisory{}
	}
	return writeFileAtomic(path, in)
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

// WriteAdvisoryReport writes the report, 0600, atomically.
func WriteAdvisoryReport(path string, r AdvisoryReport) error {
	if r.Results == nil {
		r.Results = []AdvisoryResult{}
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
