package mailbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/statefile"
)

var vnow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func vstore(t *testing.T) *Store {
	return &Store{Path: filepath.Join(t.TempDir(), "processed.json"), Now: func() time.Time { return vnow }}
}

func TestValidateAcceptsWhatRecordWrites(t *testing.T) {
	s := vstore(t)
	l := &Log{}
	s.Record(l, []Processed{
		{ID: "AAA", Subject: "Advisory", HasCVE: true},
		{ID: "BBB", Subject: strings.Repeat("é", 800), Ref: strings.Repeat("r", 900)}, // clipped, not refused
		{ID: "  "}, // blank id: skipped by Record
	})
	if err := l.Validate(vnow); err != nil {
		t.Fatalf("a log Record built was refused: %v", err)
	}
	if len(l.Entries) != 2 {
		t.Fatalf("entries: %d", len(l.Entries))
	}
	for _, e := range l.Entries {
		if len(e.Subject) > maxSubject || len(e.Ref) > maxRef || strings.ContainsRune(e.Subject, '�') {
			t.Errorf("not clipped cleanly: %d %d", len(e.Subject), len(e.Ref))
		}
	}
	if err := s.Save(l); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesWhatCouldMisleadTheCleanup(t *testing.T) {
	good := Processed{ID: "AAA", ReadAt: vnow}
	for name, l := range map[string]*Log{
		"no id":         {Entries: []Processed{{ID: " ", ReadAt: vnow}}},
		"huge id":       {Entries: []Processed{{ID: strings.Repeat("x", maxIDLen+1), ReadAt: vnow}}},
		"repeated id":   {Entries: []Processed{good, good}},
		"future ReadAt": {Entries: []Processed{{ID: "A", ReadAt: vnow.Add(90 * 24 * time.Hour)}}},
		"huge subject":  {Entries: []Processed{{ID: "A", ReadAt: vnow, Subject: strings.Repeat("s", maxSubject+1)}}},
		"too many":      {Entries: make([]Processed, maxEntries+1)},
	} {
		if err := l.Validate(vnow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&Log{Entries: []Processed{{ID: "A", ReadAt: vnow.Add(time.Hour)}}}).Validate(vnow); err != nil {
		t.Errorf("clock skew refused: %v", err)
	}
}

func TestARefusedSaveLeavesTheLogAlone(t *testing.T) {
	s := vstore(t)
	good := &Log{}
	s.Record(good, []Processed{{ID: "AAA", Subject: "x"}})
	if err := s.Save(good); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Path)
	bad := &Log{Entries: []Processed{{ID: "A", ReadAt: vnow.Add(365 * 24 * time.Hour)}}}
	if err := s.Save(bad); !errors.Is(err, statefile.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if after, _ := os.ReadFile(s.Path); string(after) != string(before) {
		t.Error("a refused save changed the file")
	}
}

// The processed log fails closed: a damaged one stops the cleanup lane loudly
// rather than letting it archive on a record nobody can vouch for.
func TestLoadFailsClosedOnAnInvalidLog(t *testing.T) {
	s := vstore(t)
	if err := os.WriteFile(s.Path, []byte(`{"entries":[{"id":"A","read_at":"2099-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := s.Load()
	if err == nil || l != nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("l=%v err=%v", l, err)
	}
	// a missing log is still an empty one
	if l, err := (&Store{Path: filepath.Join(t.TempDir(), "none"), Now: s.Now}).Load(); err != nil || l == nil || len(l.Entries) != 0 {
		t.Fatalf("missing: %v %v", l, err)
	}
}
