package supplier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SeenEntry is what the lane remembers about a request it has reported, so a
// thread that stays in the mailbox is reported once, and so a later message in
// it (the requester sending the website, the form arriving) is noticed and the
// existing Kanban item updated instead of a second one filed.
//
// It holds a label, dates, a verdict and a ticket key: no supplier name, no
// address, no text from the request.
type SeenEntry struct {
	// Reported is when the digest first told the team about the request.
	Reported time.Time `json:"reported"`
	// LastReceived is the newest message of the thread when it was last judged.
	// A message newer than this is new information. Received time, not message
	// id: an id changes when a person files the message in another folder.
	LastReceived time.Time `json:"last_received,omitempty"`
	// Verdict is the last judgement: yes, no or unsure.
	Verdict string `json:"verdict,omitempty"`
	// FormState is whether the form was read, linked, unreadable or none.
	FormState FormState `json:"form_state,omitempty"`
	// Ticket and TicketURL are the Kanban item, when there is one.
	Ticket    string `json:"ticket,omitempty"`
	TicketURL string `json:"ticket_url,omitempty"`
}

// UnmarshalJSON reads the current object form and the first version of the
// record, in which a label mapped to a bare time. A request recorded that way
// is reported once and never judged again (it has no LastReceived).
func (e *SeenEntry) UnmarshalJSON(b []byte) error {
	var t time.Time
	if err := json.Unmarshal(b, &t); err == nil {
		*e = SeenEntry{Reported: t}
		return nil
	}
	type plain SeenEntry
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*e = SeenEntry(p)
	return nil
}

// SeenRecord is one request to record: its label and what to remember.
type SeenRecord struct {
	Label string    `json:"label"`
	Entry SeenEntry `json:"entry"`
}

// Seen is the lane's record of reported requests, by label.
type Seen map[string]SeenEntry

// keepFor is how long an entry is kept. Longer than any window the lane looks
// back over, so a request cannot come round again before it is forgotten.
const keepFor = 90 * 24 * time.Hour

// LoadSeen reads the file. A missing file is an empty record; one that does not
// parse is an error, so a damaged record stops the lane instead of silently
// re-reporting everything.
func LoadSeen(path string) (Seen, error) {
	s := Seen{}
	if path == "" {
		return s, nil
	}
	// #nosec G304 -- the lane's own record under $FLEET_HOME/state.
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", path, err)
	}
	return s, nil
}

// Has reports whether a request label was already reported.
func (s Seen) Has(label string) bool { _, ok := s[label]; return ok }

// Record adds labels as reported at a time, with nothing else remembered.
func (s Seen) Record(labels []string, now time.Time) {
	for _, l := range labels {
		s.RecordEntry(l, SeenEntry{}, now)
	}
}

// RecordEntry remembers a request. Reported keeps its first value when the
// request was already recorded, so "first reported" stays true across updates.
// Entries older than keepFor are dropped.
func (s Seen) RecordEntry(label string, e SeenEntry, now time.Time) {
	if prev, ok := s[label]; ok && !prev.Reported.IsZero() {
		e.Reported = prev.Reported
	} else if e.Reported.IsZero() {
		e.Reported = now
	}
	s[label] = e
	for k, v := range s {
		if now.Sub(v.Reported) > keepFor {
			delete(s, k)
		}
	}
}

// Save writes the file atomically, readable by its owner only.
func (s Seen) Save(path string) error {
	if path == "" {
		return errors.New("no path to save the record to")
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".supplier-seen-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := os.Chmod(name, 0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
