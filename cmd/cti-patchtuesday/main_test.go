package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// flags mirrors the source flags main defines, so the guard is tested
// against the same names it looks up.
func flags(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("cti-patchtuesday", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool("dry-run", false, "")
	fs.Bool("subject-only", false, "")
	fs.String("month", "", "")
	fs.String("url-msrc", "", "")
	fs.String("url-bleeping", "", "")
	fs.String("url-qualys", "", "")
	fs.String("drop-dir", "", "")
	fs.String("provider", "", "")
	fs.Bool("mark-sent", false, "")
	fs.String("json", "", "")
	fs.String("out", "", "")
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return fs
}

func TestDryRunRefusesSourceOverrides(t *testing.T) {
	for _, args := range [][]string{
		{"--dry-run", "--url-msrc", "https://attacker.example/x"},
		{"--dry-run", "--url-bleeping", "https://attacker.example/x"},
		{"--dry-run", "--url-qualys", "https://attacker.example/x"},
		{"--dry-run", "--drop-dir", "/etc"},
		{"--dry-run", "--drop-dir="},
		{"--dry-run", "--url-qualys="},
		{"--dry-run", "--month", "2026-08", "--url-qualys", "http://192.0.2.1/"},
		{"--url-bleeping", "https://attacker.example/x", "--dry-run"},
		{"--dry-run=true", "--url-msrc", "https://attacker.example/x"},
	} {
		err := refuseDryRunOverrides(flags(t, args...))
		if err == nil {
			t.Errorf("%v: accepted", args)
			continue
		}
		if !strings.Contains(err.Error(), "--dry-run with --") {
			t.Errorf("%v: unexpected message %q", args, err)
		}
	}
}

func TestDryRunNamesEveryOverride(t *testing.T) {
	err := refuseDryRunOverrides(flags(t, "--dry-run",
		"--url-qualys", "a", "--drop-dir", "b", "--url-bleeping", "c"))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"--drop-dir", "--url-bleeping", "--url-qualys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not name %s", err, want)
		}
	}
}

func TestDryRunAllowsTheStandardSources(t *testing.T) {
	for _, args := range [][]string{
		{"--dry-run"},
		{"--dry-run", "--month", "2026-08"},
		{"--dry-run", "--provider", "none"},
		{"--dry-run", "--url-msrc", "none"},
		{"--dry-run", "--url-msrc", "NONE"},
		// Not a dry run: the operator's by-hand overrides keep working.
		{"--url-qualys", "https://blog.example.com/x", "--drop-dir", "/tmp/x"},
		{"--url-msrc", "https://api.example.com/cvrf"},
	} {
		if err := refuseDryRunOverrides(flags(t, args...)); err != nil {
			t.Errorf("%v: refused: %v", args, err)
		}
	}
}

func TestADryRunCannotBeTurnedOff(t *testing.T) {
	for _, args := range [][]string{
		{"--dry-run", "--dry-run=false", "--mark-sent"},
		{"--dry-run", "-dry-run=false", "--json", "/tmp/x.json"},
		{"--dry-run", "--dry-run=0", "--url-qualys", "https://attacker.example/x"},
		{"--dry-run=false"},
	} {
		fs := flags(t, args...)
		if fs.Lookup("dry-run").Value.String() == "true" {
			t.Fatalf("%v: test setup expected the final value to be false", args)
		}
		if err := refuseDryRunUndone(args, false); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
	for _, args := range [][]string{
		{"--dry-run"},
		{"--month", "2026-08", "--mark-sent"},
		{"--out", "d.html"},
	} {
		dry := flags(t, args...).Lookup("dry-run").Value.String() == "true"
		if err := refuseDryRunUndone(args, dry); err != nil {
			t.Errorf("%v: refused: %v", args, err)
		}
	}
}
