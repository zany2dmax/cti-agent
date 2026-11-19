package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdvisoryInputCapsAndRoundTrips(t *testing.T) {
	big := NewAdvisory("x", time.Unix(0, 0), "s", "subj", false, strings.Repeat("a", MaxAdvisoryBody+10))
	if !big.Truncated || len(big.Body) != MaxAdvisoryBody {
		t.Fatalf("body not capped: %d %v", len(big.Body), big.Truncated)
	}
	var msgs []Advisory
	for i := 0; i < MaxAdvisoriesPerRun+3; i++ {
		msgs = append(msgs, NewAdvisory("id", time.Unix(int64(i), 0), "s", "subj", false, "b"))
	}
	p := filepath.Join(t.TempDir(), "in.json")
	if err := WriteAdvisoryInput(p, msgs, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	in, err := ReadAdvisoryInput(p)
	if err != nil || len(in.Messages) != MaxAdvisoriesPerRun || in.Dropped != 3 {
		t.Fatalf("read back: %v %d %d", err, len(in.Messages), in.Dropped)
	}
	if err := os.WriteFile(p, []byte(`{"schema":"cti-advisory-input/2","messages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAdvisoryInput(p); err == nil {
		t.Fatal("a wrong schema was read")
	}
}

func TestOrderPutsAuthenticatedFeedsFirstThenOldest(t *testing.T) {
	got := Order([]Advisory{
		{ID: "new", Received: time.Unix(3, 0)},
		{ID: "feed", Received: time.Unix(9, 0), Trusted: true},
		{ID: "old", Received: time.Unix(1, 0)},
	})
	var ids []string
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "feed,old,new" {
		t.Fatalf("order = %v", ids)
	}
}
