package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// blockingFetcher returns the first report and then never returns, so the
// run can be killed between two reports.
type blockingFetcher struct{ fakeFetcher }

func (b *blockingFetcher) AppReport(ctx context.Context, r appscan.ReportRequest) (appscan.Report, error) {
	if r.AppID != "1" {
		select {} // the scanner never answers: the run is killed here
	}
	return b.fakeFetcher.AppReport(ctx, r)
}

// A run killed mid-way (SIGKILL: no deferred cleanup, no trap) leaves nothing
// on disk that holds the scan session: each report is redacted before it is
// written, so whatever a killed run leaves behind is the redacted copy.
func TestAKilledRunLeavesNoScanSessionOnDisk(t *testing.T) {
	if dir := os.Getenv("CTI_APPREPORT_KILLED_RUN_DIR"); dir != "" {
		// The child: fetch two reports; the second never comes back.
		fetchAll(context.Background(), &blockingFetcher{}, dir, targets("1", "2"), 10, false, time.Hour)
		return
	}
	dir := filepath.Join(t.TempDir(), "reports")
	cmd := exec.Command(os.Args[0], "-test.run=^TestAKilledRunLeavesNoScanSessionOnDisk$") // #nosec G204 G702 -- this test binary
	cmd.Env = append(os.Environ(), "CTI_APPREPORT_KILLED_RUN_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, appscan.ReportFile("id:1"))
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(first); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("the child never wrote its first report")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // into the second, blocking, report
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- the test's own temp dir
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("SCANSESSION")) || (appscan.IsZip(b) && strings.Contains(unzipped(t, b), "SCANSESSION")) {
			t.Errorf("%s holds the scan session after a killed run", filepath.Base(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if text := unzipped(t, mustRead(t, first)); !strings.Contains(text, "app 1") {
		t.Fatalf("the report written before the kill is not the redacted report: %q", text)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	return b
}
