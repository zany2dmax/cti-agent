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
	if _, err := WriteAdvisoryInput(p, msgs, time.Unix(0, 0)); err != nil {
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

// A message the writer cannot match to a report line is left out and named;
// header fields are cleaned; the rest are written.
func TestAdvisoryInputRefusesWhatItCannotUse(t *testing.T) {
	good := NewAdvisory("good-id", time.Now(), "a@vendor.example", "ok\x00\x07 subject", false, "CVE-2026-1 body\x00")
	msgs := []Advisory{
		good,
		{ID: "", Received: time.Now(), Subject: "no id"},
		{ID: "line\nbreak", Received: time.Now(), Subject: "bad id"},
		{ID: "future", Received: time.Now().Add(72 * time.Hour), Subject: "from the future"},
		{ID: "zero-time", Subject: "no time"},
	}
	p := filepath.Join(t.TempDir(), "in.json")
	refused, err := WriteAdvisoryInput(p, msgs, time.Now())
	if err != nil || len(refused) != 4 {
		t.Fatalf("err %v, refused %d: %v", err, len(refused), refused)
	}
	in, err := ReadAdvisoryInput(p)
	if err != nil || len(in.Messages) != 1 || in.Refused != 0 {
		t.Fatalf("read back: %v %+v", err, in)
	}
	if strings.ContainsAny(in.Messages[0].Subject, "\x00\x07") || strings.Contains(in.Messages[0].Body, "\x00") {
		t.Errorf("control characters survived: %q %q", in.Messages[0].Subject, in.Messages[0].Body)
	}
	// A tampered file is checked again on the way in.
	bad := `{"schema":"cti-advisory-input/1","messages":[{"id":"","received":"2026-01-01T00:00:00Z"},{"id":"ok","received":"2026-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err = ReadAdvisoryInput(p)
	if err != nil || len(in.Messages) != 1 || in.Refused != 1 {
		t.Fatalf("tampered file: %v %+v", err, in)
	}
}

func TestAdvisoryReportIsCheckedBeforeItIsWritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rep.json")
	ok := AdvisoryReport{Schema: AdvisoryReportSchema, Generated: time.Now(), Read: 2, Triaged: 1,
		Results: []AdvisoryResult{{MessageID: "", Subject: "s\x01", Sender: "Jane <jane@vendor.example>"}}}
	if err := WriteAdvisoryReport(p, ok); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"(no id)"`) || strings.Contains(string(b), "jane@") || strings.Contains(string(b), `\u0001`) {
		t.Errorf("report not repaired:\n%s", b)
	}
	for name, r := range map[string]AdvisoryReport{
		"wrong schema":     {Schema: "x", Read: 1},
		"triaged > read":   {Schema: AdvisoryReportSchema, Read: 1, Triaged: 2},
		"negative cost":    {Schema: AdvisoryReportSchema, CostUSD: -1},
		"negative tokens":  {Schema: AdvisoryReportSchema, Tokens: -5},
		"negative dropped": {Schema: AdvisoryReportSchema, Dropped: -1},
	} {
		if err := WriteAdvisoryReport(filepath.Join(t.TempDir(), "r.json"), r); err == nil {
			t.Errorf("%s was written", name)
		}
	}
}
