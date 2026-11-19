package appscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var dnow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func TestCommitDeliveredRecordsGoodLinesAndReportsBadOnes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "delivered.json")
	in := strings.Join([]string{
		"id:100\tscan-1\tsent",
		"id:200\tscan-2\theld: no owner on file",
		"id:300\tscan-3\tmaybe",                          // not sent or held
		"id:400\tscan-4\tsent\x1b[31m",                   // control character
		"\tscan-5\tsent",                                 // empty key
		"id:600\t" + strings.Repeat("r", 600) + "\tsent", // ref too long
		"only two\tfields",
	}, "\n")
	n, bad, err := CommitDelivered(p, strings.NewReader(in), dnow)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(bad) != 5 {
		t.Fatalf("recorded %d, reported %d: %v", n, len(bad), bad)
	}
	l, err := LoadDeliveredLog(p)
	if err != nil || len(l) != 2 || l["id:100"].Status != "sent" {
		t.Fatalf("%v %v", l, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	// no temp files left, and nothing named after the old fixed ".tmp"
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Errorf("left files: %v", entries)
	}
}

func TestDeliveredLogValidateRefusesAFutureDateAndAnOddStatus(t *testing.T) {
	good := DeliveredEntry{Ref: "r", At: dnow, Status: "sent"}
	for name, l := range map[string]DeliveredLog{
		"future":     {"id:1": {Ref: "r", At: dnow.Add(72 * time.Hour), Status: "sent"}},
		"odd status": {"id:1": {Ref: "r", At: dnow, Status: "SENT!!"}},
		"no ref":     {"id:1": {At: dnow, Status: "sent"}},
		"empty key":  {"": good},
	} {
		if err := l.Validate(dnow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (DeliveredLog{"id:1": good, "Some App": {Ref: "r", At: dnow, Status: "held: why"}}).Validate(dnow); err != nil {
		t.Errorf("a normal log was refused: %v", err)
	}
}

func TestAnInvalidDeliveredLogStopsTheCommitInsteadOfBeingOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "delivered.json")
	bad := `{"id:1":{"ref":"r","at":"2099-01-01T00:00:00Z","status":"sent"}}`
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CommitDelivered(p, strings.NewReader("id:2\tr\tsent"), dnow); err == nil {
		t.Fatal("committed on top of an invalid log")
	}
	if b, _ := os.ReadFile(p); string(b) != bad {
		t.Error("the invalid log was overwritten")
	}
}
