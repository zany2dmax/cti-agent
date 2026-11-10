package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/qualysrl"
)

// ownerSource is a fake scanner for the owner report. It counts its calls:
// the lane spends a shared API budget, so the number is part of the contract.
type ownerSource struct {
	findings              []appscan.Finding
	findingCalls, kbCalls int
	kbIDs                 []string
	kbErr                 error
}

func (o *ownerSource) OwnerFindings(_ context.Context, appID string) ([]appscan.Finding, error) {
	o.findingCalls++
	return o.findings, nil
}

func (o *ownerSource) Remedies(_ context.Context, ids []string) (map[string]appscan.Remedy, error) {
	o.kbCalls++
	o.kbIDs = append(o.kbIDs, ids...)
	if o.kbErr != nil {
		return nil, o.kbErr
	}
	return map[string]appscan.Remedy{"150123": {Solution: "Set HttpOnly."}}, nil
}

func sampleFindings() []appscan.Finding {
	return []appscan.Finding{
		{ID: "150123", Title: "Cookie without HttpOnly", Severity: 2, Kind: "VULNERABILITY",
			URL: "https://shop.example.com/", Param: "sid", Status: "ACTIVE", AppURL: "https://shop.example.com",
			Evidence: &appscan.Evidence{Method: "GET", Link: "https://shop.example.com/",
				Proof: appscan.Redact("sid=live-value; path=/; domain=shop.example.com")}},
		{ID: "150009", Title: "Links Crawled", Severity: 1, Kind: "INFORMATION_GATHERED"},
	}
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
	f := &ownerSource{findings: sampleFindings()}
	if rc := doDeliveries(context.Background(), f, writeDeliveries(t, tmp), out, 10, time.Minute); rc != exitOK {
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
	for _, want := range []string{"Web application scan report", "https://shop.example.com", "Set HttpOnly."} {
		if !strings.Contains(string(att), want) {
			t.Errorf("attachment lacks %q", want)
		}
	}
	// One finding search per application, one knowledge-base lookup for the
	// run, and none for information gathered (listed by title only).
	if f.findingCalls != 1 || f.kbCalls != 1 || strings.Join(f.kbIDs, ",") != "150123" {
		t.Errorf("API calls: %d finding search(es), %d KB lookup(s) for %v", f.findingCalls, f.kbCalls, f.kbIDs)
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
	fs := sampleFindings()
	fs[0].Title = strings.Repeat("x", appscan.MaxMailAttachment)
	if rc := doDeliveries(context.Background(), &ownerSource{findings: fs}, writeDeliveries(t, tmp), out, 10, time.Minute); rc != exitOK {
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
	if rc := doDeliveries(context.Background(), nil, writeDeliveries(t, tmp), out, 10, time.Minute); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	send, _ := os.ReadFile(filepath.Join(out, "send.tsv"))
	if !strings.HasPrefix(string(send), "id:1\t") || !strings.HasSuffix(string(send), "\t\n") {
		t.Errorf("send.tsv %q", send)
	}
}

func TestDeliveriesWaitWhenTheKnowledgeBaseIsOutOfBudget(t *testing.T) {
	// A report without its fixes, once sent, is never sent again - so an
	// exhausted budget holds every report for tomorrow instead.
	tmp := t.TempDir()
	out := filepath.Join(tmp, "work")
	f := &ownerSource{findings: sampleFindings(), kbErr: fmt.Errorf("kb chunk: %w", qualysrl.ErrBudget)}
	if rc := doDeliveries(context.Background(), f, writeDeliveries(t, tmp), out, 10, time.Minute); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	if send, _ := os.ReadFile(filepath.Join(out, "send.tsv")); len(strings.TrimSpace(string(send))) != 0 {
		t.Errorf("a report went out without its fixes: send.tsv %q", send)
	}
}
