package main

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// reportFetcher returns a real zip holding a report with a live session in it.
type reportFetcher struct{ body string }

func (reportFetcher) Name() string { return "fake-dast" }

func (f reportFetcher) AppReport(_ context.Context, r appscan.ReportRequest) (appscan.Report, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, _ := w.Create("report.html")
	_, _ = fw.Write([]byte(f.body))
	_ = w.Close()
	return appscan.Report{Provider: "fake-dast", AppID: r.AppID, App: r.App, Body: buf.Bytes()}, nil
}

func writeDeliveries(t *testing.T, dir string) string {
	t.Helper()
	fin := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	df := appscan.DeliveriesFile{Deliveries: []appscan.Delivery{
		{Key: "id:1", AppID: "1", App: "Shop Front", ScanRef: "was/1.1", Finished: fin, AuthLabel: "authenticated scan"},
		{Key: "id:2", AppID: "2", App: "Broken", ScanRef: "was/2.1", Hold: "the scan did not finish"},
		{Key: "name:x", App: "No Id", ScanRef: "was/3.1", Hold: "no web app id", Retry: true},
	}}
	p := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(p, df.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeliveriesWriteRedactedMail(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "work")
	f := reportFetcher{body: "<html>Cookie: SESSION=live-value</html>"}
	if rc := doDeliveries(context.Background(), f, writeDeliveries(t, tmp), out, 10, false, time.Minute); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	send, _ := os.ReadFile(filepath.Join(out, "send.tsv"))
	rows := strings.Split(strings.TrimSpace(string(send)), "\n")
	if len(rows) != 1 {
		t.Fatalf("send.tsv %q", send)
	}
	cols := strings.Split(rows[0], "\t")
	if len(cols) != 5 || cols[0] != "id:1" || cols[1] != "was/1.1" || cols[2] != "1" {
		t.Fatalf("row %q", cols)
	}
	if filepath.Base(cols[4]) != "shop-front-scan-report-2026-11-02.html" {
		t.Errorf("attachment %q", cols[4])
	}
	att, err := os.ReadFile(cols[4])
	if err != nil || strings.Contains(string(att), "live-value") {
		t.Fatalf("attachment not redacted (%v): %s", err, att)
	}
	if _, err := os.Stat(filepath.Join(out, appscan.ReportFile("id:1"))); !os.IsNotExist(err) {
		t.Error("the unredacted report was left on disk")
	}
	mail, _ := os.ReadFile(filepath.Join(cols[3], "mail.html"))
	if !strings.Contains(string(mail), "is attached") {
		t.Errorf("mail %s", mail)
	}
	held, _ := os.ReadFile(filepath.Join(out, "held.tsv"))
	if string(held) != "id:2\twas/2.1\theld: the scan did not finish\n" {
		t.Errorf("held.tsv %q - a retryable hold must not be recorded", held)
	}
	text, _ := os.ReadFile(filepath.Join(out, "held.txt"))
	if strings.Count(string(text), "\n") != 2 {
		t.Errorf("held.txt %q", text)
	}
}

func TestDeliveriesTooLargeGoesWithoutAttachment(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "work")
	big := "<html>" + strings.Repeat("x", appscan.MaxMailAttachment) + "</html>"
	if rc := doDeliveries(context.Background(), reportFetcher{body: big}, writeDeliveries(t, tmp), out, 10, false, time.Minute); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	send, _ := os.ReadFile(filepath.Join(out, "send.tsv"))
	cols := strings.Split(strings.TrimSpace(string(send)), "\t")
	if len(cols) != 4 && (len(cols) != 5 || cols[4] != "") {
		t.Fatalf("a too-large report was attached: %q", cols)
	}
	mail, _ := os.ReadFile(filepath.Join(cols[3], "mail.html"))
	if !strings.Contains(string(mail), "over the 3 MB email limit") {
		t.Errorf("mail %s", mail)
	}
}

func TestDeliveriesDryRunFetchesNothing(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "work")
	if rc := doDeliveries(context.Background(), nil, writeDeliveries(t, tmp), out, 10, false, time.Minute); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	send, _ := os.ReadFile(filepath.Join(out, "send.tsv"))
	if !strings.HasPrefix(string(send), "id:1\t") || !strings.HasSuffix(string(send), "\t\n") {
		t.Errorf("send.tsv %q", send)
	}
}
