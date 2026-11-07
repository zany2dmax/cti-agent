package main

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// A scanner vendor is named in wiring.go and nowhere else in this command, so
// adding one cannot mean editing the lane. Same for the vendor-neutral
// package: a vendor imports appscan, never the reverse.
func TestOnlyWiringNamesAVendor(t *testing.T) {
	for _, dir := range []string{".", "../../internal/appscan"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || filepath.Base(f) == "wiring.go" {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, im := range af.Imports {
				if strings.Contains(im.Path.Value, "internal/appscan/qualys") {
					t.Errorf("%s imports a vendor package (%s); only cmd/cti-appscan/wiring.go may",
						f, im.Path.Value)
				}
			}
		}
	}
	if _, err := os.Stat("wiring.go"); err != nil {
		t.Fatal(err)
	}
}

type fakeScanner struct{ asked []string }

func (*fakeScanner) Name() string { return "fake-dast" }
func (f *fakeScanner) Findings(_ context.Context, s appscan.ScanResult, _ time.Time) ([]appscan.Finding, error) {
	f.asked = append(f.asked, s.App)
	return []appscan.Finding{{ID: "1"}}, nil
}

// The lane works through the interfaces: a scanner with only some of the
// capabilities is used for those and skipped for the rest, and detail is only
// asked of the scanner that produced the scan.
func TestLaneUsesWhateverTheScannerCanDo(t *testing.T) {
	f := &fakeScanner{}
	scans := []appscan.ScanResult{
		{App: "mine", Provider: "fake-dast"},
		{App: "other vendor", Provider: "someone-else"},
		{App: "no mail", Provider: "fake-dast", NoNotification: true},
	}
	attachDetail(context.Background(), f, scans, time.Now())
	if len(f.asked) != 1 || f.asked[0] != "mine" {
		t.Fatalf("detail asked for %v, want only [mine]", f.asked)
	}
	if len(scans[0].Findings) != 1 || scans[1].Findings != nil {
		t.Errorf("findings attached wrongly: %+v", scans)
	}

	// No Reconciler, no OpenFetcher, no RemedyFetcher: each is a no-op.
	if got := reconcile(context.Background(), f, scans, time.Now()); len(got) != len(scans) {
		t.Errorf("reconcile without the capability changed the scans")
	}
	attachOpen(context.Background(), f, scans)
	attachRemedies(context.Background(), f, scans)
	if scans[0].OpenFetched {
		t.Error("open findings marked fetched by a scanner that cannot fetch them")
	}
}
