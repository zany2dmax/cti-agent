package triage

// THE DAILY BATCH
//
// The digest's ingest reads every message in the mailbox and keeps only the
// CVEs. A message with no CVE - a campaign write-up, a malicious-package
// warning, a vendor advisory with no ID yet - used to be counted and then
// forgotten. With TRIAGE_ENABLED, ingest saves those messages here
// (AdvisoryInput), and cti-triage --batch runs each through the reader, the
// Falcon lookups and the judge, writing one AdvisoryReport that brief.py
// renders as FLEET ADVISORIES.
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

// Advisory is one message with no CVE, as ingest read it.
type Advisory struct {
	ID        string    `json:"id"`
	Received  time.Time `json:"received"`
	Sender    string    `json:"sender"`
	Subject   string    `json:"subject"`
	Trusted   bool      `json:"trusted_sender"` // an authenticated feed sender
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

// NewAdvisory caps the body.
func NewAdvisory(id string, received time.Time, sender, subject string, trusted bool, body string) Advisory {
	a := Advisory{ID: id, Received: received, Sender: sender, Subject: subject, Trusted: trusted, Body: body}
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
	Verdicts  *Verdicts `json:"verdicts,omitempty"`
	Problems  []string  `json:"problems,omitempty"` // a stage that failed; the verdicts say what survived
	Skipped   string    `json:"not_triaged,omitempty"`
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
