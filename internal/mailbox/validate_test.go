package mailbox

import (
	"errors"
	"fmt"
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

// The processed log is REPAIRED on load, not rejected: an entry from an older
// version, or dated ahead by a clock that stepped back, must not stop the
// cleanup lane until somebody deletes the file by hand. Only a file that does
// not parse fails closed.
func TestLoadRepairsWhatItCanAndFailsClosedOnlyOnAnUnparseableLog(t *testing.T) {
	s := vstore(t)
	body := `{"entries":[` +
		`{"id":"A","read_at":"2099-01-01T00:00:00Z","subject":"x"},` + // clock stepped back
		`{"id":"A","read_at":"2026-11-19T11:00:00Z"},` + // a repeat of A
		`{"id":"","read_at":"2026-11-19T11:00:00Z"},` + // no id
		`{"id":"B","read_at":"2026-11-19T11:00:00Z","subject":"` + strings.Repeat("s", 2000) + `"}` + // an older version allowed this
		`]}`
	if err := os.WriteFile(s.Path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := s.Load()
	if err != nil || l == nil {
		t.Fatalf("a log that parses must not stop the lane: l=%v err=%v", l, err)
	}
	if len(l.Entries) != 2 {
		t.Fatalf("want A (once) and B, got %+v", l.Entries)
	}
	byID := map[string]Processed{}
	for _, e := range l.Entries {
		byID[e.ID] = e
	}
	if !byID["A"].ReadAt.Equal(vnow) {
		t.Errorf("a future read time should be pulled back to now so it expires normally: %v", byID["A"].ReadAt)
	}
	if len(byID["B"].Subject) > maxSubject {
		t.Errorf("a long subject was not clipped: %d", len(byID["B"].Subject))
	}
	if err := l.Validate(vnow); err != nil {
		t.Errorf("a repaired log must validate: %v", err)
	}
	if err := s.Save(l); err != nil {
		t.Errorf("a repaired log could not be saved: %v", err)
	}

	// unparseable: fail closed
	if err := os.WriteFile(s.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := s.Load(); err == nil || l != nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("an unparseable log must fail closed: l=%v err=%v", l, err)
	}
	// a missing log is still an empty one
	if l, err := (&Store{Path: filepath.Join(t.TempDir(), "none"), Now: s.Now}).Load(); err != nil || l == nil || len(l.Entries) != 0 {
		t.Fatalf("missing: %v %v", l, err)
	}
}

// 30,000 entries is about 15 MB indented: the byte cap must not be what stops a
// busy mailbox before the entry cap does.
func TestALargeLegitimateLogFitsTheCap(t *testing.T) {
	s := vstore(t)
	l := &Log{}
	var seen []Processed
	for i := 0; i < 30000; i++ {
		seen = append(seen, Processed{ID: strings.Repeat("x", 150) + fmt.Sprint(i), Subject: strings.Repeat("s", 120), ReadAt: vnow})
	}
	s.Record(l, seen)
	if err := s.Save(l); err != nil {
		t.Fatalf("a 30,000 entry log was refused: %v", err)
	}
	if got, err := s.Load(); err != nil || len(got.Entries) != 30000 {
		t.Fatalf("%v %d", err, len(got.Entries))
	}
}
