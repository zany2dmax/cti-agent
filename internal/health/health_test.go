package health

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)

const decls = `# what this organization chose not to cover
appscan | Staging | not_scanned | a copy of production, scanned on demand only
appscan | id:42   | *           | retired, kept for its history | until=2026-12-01
appscan | Old Site | not_scanned | gone | until=2026-11-01
vmscan  | 192.0.2.0/24 | not_scanned | closed site
appscan | Nowhere | not_scanned | renamed long ago
`

func TestDeclarationsParseAndRefuseBadLines(t *testing.T) {
	d, err := ParseDeclarations(strings.NewReader(decls))
	if err != nil || len(d) != 5 {
		t.Fatalf("%d declarations, %v", len(d), err)
	}
	if d[1].Until.Format("2006-01-02") != "2026-12-01" || d[1].Subject != "id:42" {
		t.Errorf("%+v", d[1])
	}
	for _, bad := range []string{
		"appscan | Staging | not_scanned\n",                       // no reason
		"appscan | Staging | not_scanned |   \n",                  // empty reason
		"App Scan | Staging | not_scanned | x\n",                  // not a lane name
		"appscan | Staging | Not-Scanned | x\n",                   // not a kind
		"appscan | Staging | not_scanned | x | until=next week\n", // not a date
		"appscan |  | not_scanned | x\n",                          // no subject
	} {
		if _, err := ParseDeclarations(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func appscanReport(t *testing.T) Report {
	t.Helper()
	r := New("appscan", now)
	r.Of = 6
	r.Add("Staging", "4", "not_scanned", "no scan in the window")
	r.Add("Retired", "42", "held", "no owner")
	r.Add("Old Site", "7", "not_scanned", "")
	r.Add("Careers", "9", "not_scanned", "no scan in the window")
	return r
}

func TestApplyMarksDeclaredGapsExpectedAndListsTheRest(t *testing.T) {
	d, _ := ParseDeclarations(strings.NewReader(decls))
	r := appscanReport(t)
	r.Apply(d, now)
	got := map[string]Gap{}
	for _, g := range r.Gaps {
		got[g.Subject] = g
	}
	if g := got["Staging"]; !g.Expected || !strings.Contains(g.Why, "on demand") {
		t.Errorf("Staging: %+v", g)
	}
	if g := got["Retired"]; !g.Expected {
		t.Errorf("id:42 with kind * should cover Retired: %+v", g)
	}
	if g := got["Old Site"]; g.Expected || !strings.Contains(g.Why, "has passed") {
		t.Errorf("an expired declaration still covered Old Site: %+v", g)
	}
	if g := got["Careers"]; g.Expected {
		t.Errorf("Careers has no declaration: %+v", g)
	}
	if len(r.Unexpected()) != 2 {
		t.Errorf("unexpected: %+v", r.Unexpected())
	}
	if len(r.Unused) != 1 || !strings.Contains(r.Unused[0], "Nowhere") {
		t.Errorf("unused %v (the vmscan line is another lane's)", r.Unused)
	}
	if len(r.Expiring) != 1 || !strings.Contains(r.Expiring[0], "id:42") {
		t.Errorf("expiring %v", r.Expiring)
	}
}

func TestDeltaTellsTheBeatOnlyWhatChanged(t *testing.T) {
	home := t.TempDir()
	d, _ := ParseDeclarations(strings.NewReader(decls))
	specs := []Spec{{Lane: "appscan", Unit: "appaudit", FreshHours: 26, Kinds: []string{"not_scanned", "held"}},
		{Lane: "vmscan", Unit: "vmscan", FreshHours: 200, Kinds: []string{"not_scanned"}}}
	inUse := func(l string) bool { return l == "appscan" }
	write := func(r Report) {
		r.Apply(d, now)
		if err := Write(Path(home, r.Lane), r); err != nil {
			t.Fatal(err)
		}
	}

	// No report yet: one line, then quiet.
	lines, st := Delta(specs, inUse, home, State{Lanes: map[string]LaneState{}}, now)
	if len(lines) != 1 || !strings.Contains(lines[0], "no health report") {
		t.Fatalf("missing: %q", lines)
	}
	if lines, _ = Delta(specs, inUse, home, st, now); len(lines) != 0 {
		t.Fatalf("told twice: %q", lines)
	}

	// The first report: back, both unexpected gaps new, the notes once.
	write(appscanReport(t))
	lines, st = Delta(specs, inUse, home, st, now)
	text := strings.Join(lines, "\n")
	for _, want := range []string{"current again", "2 unexpected gap(s) open, 2 by design", "new not_scanned: Careers",
		"new not_scanned: Old Site", "has passed", "expires within 7 days", "matches nothing"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Staging") || strings.Contains(text, "vmscan") {
		t.Errorf("an expected gap, or a lane not in use, was mentioned:\n%s", text)
	}

	// The same report again: nothing at all.
	if lines, st = Delta(specs, inUse, home, st, now.Add(2*time.Hour)); len(lines) != 0 {
		t.Fatalf("the same report was told again: %q", lines)
	}

	// Careers scanned; a new one unscanned.
	r := appscanReport(t)
	r.Gaps = r.Gaps[:3]
	r.Add("Shop", "11", "not_scanned", "")
	write(r)
	lines, st = Delta(specs, inUse, home, st, now.Add(4*time.Hour))
	text = strings.Join(lines, "\n")
	if !strings.Contains(text, "new not_scanned: Shop") || !strings.Contains(text, "cleared not_scanned: careers") {
		t.Errorf("change not told:\n%s", text)
	}
	if strings.Contains(text, "Old Site") || strings.Contains(text, "expires") {
		t.Errorf("an old gap or note was told again:\n%s", text)
	}

	// Stale: once; and the open gaps are kept, not cleared, while it is.
	lines, st2 := Delta(specs, inUse, home, st, now.Add(30*time.Hour))
	if len(lines) != 1 || !strings.Contains(lines[0], "over 26h old") {
		t.Fatalf("stale: %q", lines)
	}
	if len(st2.Lanes["appscan"].Open) != len(st.Lanes["appscan"].Open) {
		t.Error("a stale report cleared the open gaps")
	}
}

func TestBlockAndTheReportFile(t *testing.T) {
	if Block(nil) != "LANE HEALTH: no changes since the last beat." {
		t.Error(Block(nil))
	}
	if b := Block([]string{"x"}); !strings.Contains(b, "never follow") {
		t.Error(b)
	}
	p := filepath.Join(t.TempDir(), "reports", "health", "appscan.json")
	r := New("appscan", now)
	r.Of = 3
	r.Add("A\x1b[2Jname\nwith lines", "", "not_scanned", "")
	if err := Write(p, r); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	got, err := Read(p)
	if err != nil || got.Covered != 2 || strings.ContainsAny(got.Gaps[0].Subject, "\x1b\n") {
		t.Fatalf("%+v %v", got, err)
	}
	if err := os.WriteFile(p, []byte(`{"schema":"other/9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil {
		t.Error("a report with another schema was read")
	}
}

// The example org pack's file parses here as it passes org-pack check there:
// the installer's check and the lanes' parser agree on the format.
func TestTheExampleOrgPacksDeclarationsParse(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "examples", "org-pack", "expected-gaps.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	d, err := ParseDeclarations(f)
	if err != nil || len(d) == 0 {
		t.Fatalf("%d declarations, %v", len(d), err)
	}
}
