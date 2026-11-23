package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/enrich"
)

type fixed struct{}

func (fixed) NVD([]string) map[string]enrich.NVDEntry {
	ten := json.Number("10.0")
	return map[string]enrich.NVDEntry{"CVE-2021-44228": {CVSS: &ten, CPEProducts: &[][]string{{"apache", "log4j"}}}}
}

func (fixed) EPSS(cves []string) map[string]enrich.EPSSEntry {
	return map[string]enrich.EPSSEntry{"CVE-2021-44228": {EPSS: 0.97, Pct: 1}}
}

func (fixed) KEV() map[string]enrich.KEVEntry {
	due, v, p := "2021-12-24", "Apache", "Log4j2"
	return map[string]enrich.KEVEntry{"CVE-2021-44228": {Due: &due, Vendor: &v, Product: &p}}
}

const report = `# CTI / CVE Daily Report

- Mailbox: ` + "`security@example.com`" + `

| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts | Reason |
|---|---|---|---|---:|---:|---|---|---|
| CVE-2021-44228 | PRESENT | qualys | 376160 | 12 | 100 | 2026-11-20T22:00:00Z | h1 | |
| CVE-2026-0826 | UNKNOWN | qualys |  | 0 | 0 |  |  | No mapping found |
`

// A fleet with the real fleet-db from this checkout, so the novelty read and
// the upsert are the ones the box runs.
func fleet(t *testing.T) (home, raw string) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("fleet-db needs /usr/bin/python3")
	}
	home = t.TempDir()
	code, err := filepath.Abs("../../fleet-kit/fleet")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLEET_HOME", home)
	t.Setenv("FLEET_CODE", code)
	t.Setenv("CHECKIN_BEAT_ID", "")
	raw = filepath.Join(home, "raw.md")
	if err := os.WriteFile(raw, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, raw
}

func enrichOnce(t *testing.T, args ...string) (map[string]any, string) {
	t.Helper()
	var errOut bytes.Buffer
	now := func() time.Time { return time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC) }
	code := run(args, &errOut, func(string, func(string, ...any)) enrich.Sources { return fixed{} }, now)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errOut.String())
	}
	out := args[len(args)-1]
	for i, a := range args {
		if a == "--out" {
			out = args[i+1]
		}
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d, errOut.String()
}

func TestTheDigestRunEndToEnd(t *testing.T) {
	home, raw := fleet(t)
	out := filepath.Join(home, "reports", "enriched.json")

	// No memory.db yet: novelty is unknown, not "everything is new".
	d, log := enrichOnce(t, "--report", raw, "--out", out)
	if nov := d["novelty"].(map[string]any); nov["undetermined"].(float64) != 2 {
		t.Fatalf("novelty = %v\n%s", nov, log)
	}
	if !strings.Contains(log, "upserted 2 findings to memory.db") {
		t.Fatalf("no upsert:\n%s", log)
	}
	f := d["findings"].([]any)[0].(map[string]any)
	if f["cve"] != "CVE-2021-44228" || f["priority"] != "Sev5" || f["product"] != "Apache Log4j2" {
		t.Fatalf("first finding = %v", f)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Errorf("enriched file mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(home, "reports", enrich.ProductsFile)); err != nil {
		t.Errorf("no products.json beside the enriched file: %v", err)
	}

	// The second run reads both back from fleet-db as seen before.
	d, log = enrichOnce(t, "--report", raw, "--out", out)
	nov := d["novelty"].(map[string]any)
	if nov["seen_before"].(float64) != 2 || nov["new"].(float64) != 0 {
		t.Fatalf("novelty = %v\n%s", nov, log)
	}
	f = d["findings"].([]any)[0].(map[string]any)
	if f["is_new"] != false || f["first_seen"] == nil {
		t.Fatalf("finding = %v", f)
	}

	// What fleet-db stored is what the digest scored.
	cmd := exec.Command(filepath.Join(os.Getenv("FLEET_CODE"), "bin", "fleet-db"), "findings", "--cve", "CVE-2021-44228")
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("fleet-db findings: %v %s", err, b)
	}
	if rows[0]["priority"] != "Sev5" || rows[0]["cvss"].(float64) != 10 || rows[0]["kev_due"] != "2021-12-24" {
		t.Fatalf("stored = %v", rows[0])
	}
}

func TestNoDBWritesNothingToMemory(t *testing.T) {
	home, raw := fleet(t)
	_, log := enrichOnce(t, "--report", raw, "--out", filepath.Join(home, "e.json"), "--no-db")
	if strings.Contains(log, "upserted") {
		t.Fatalf("--no-db upserted:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(home, "state", "memory.db")); err == nil {
		t.Fatal("--no-db created memory.db")
	}
}

func TestAMissingFleetDBIsLoud(t *testing.T) {
	home, raw := fleet(t)
	t.Setenv("FLEET_CODE", t.TempDir())
	_, log := enrichOnce(t, "--report", raw, "--out", filepath.Join(home, "e.json"))
	if !strings.Contains(log, "WARNING: fleet-db not found") {
		t.Fatalf("silent about the missing upsert:\n%s", log)
	}
}

func TestTheScoutListNeedsNoReport(t *testing.T) {
	home, _ := fleet(t)
	d, _ := enrichOnce(t, "--cves", "cve-2021-44228,bogus", "--skip-nvd", "--no-db", "--out", filepath.Join(home, "s.json"))
	f := d["findings"].([]any)
	if len(f) != 1 || f[0].(map[string]any)["provider"] != "scout" {
		t.Fatalf("findings = %v", f)
	}
	if _, ok := f[0].(map[string]any)["cvss"]; ok {
		t.Error("--skip-nvd still has NVD keys")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--out", "x"},
		{"--report", "r", "--cves", "c", "--out", "x"},
		{"--report", "r"},
		{"--report", "r", "--out", "x", "extra"},
		{"--bogus"},
	} {
		var errOut bytes.Buffer
		if code := run(args, &errOut, nil, time.Now); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestAMissingReportIsAnError(t *testing.T) {
	home, _ := fleet(t)
	var errOut bytes.Buffer
	code := run([]string{"--report", filepath.Join(home, "nope.md"), "--out", filepath.Join(home, "e.json")}, &errOut,
		func(string, func(string, ...any)) enrich.Sources { return fixed{} }, time.Now)
	if code != 1 || !strings.Contains(errOut.String(), "nope.md") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}
