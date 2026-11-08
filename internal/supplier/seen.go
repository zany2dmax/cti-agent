package supplier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Seen remembers which requests the digest has already told the team about, by
// the request's label, so a thread that stays in the mailbox for days is
// reported once. It is a small JSON file written atomically, like the other
// lanes' logs, and it holds a label and a date: no supplier name, no address.
type Seen map[string]time.Time

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

// Set returns the labels as a lookup, for Collect.
func (s Seen) Set() map[string]bool {
	m := make(map[string]bool, len(s))
	for k := range s {
		m[k] = true
	}
	return m
}

// Record adds labels as reported at a time and drops entries older than keepFor.
func (s Seen) Record(labels []string, now time.Time) {
	for _, l := range labels {
		s[l] = now
	}
	for k, t := range s {
		if now.Sub(t) > keepFor {
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
