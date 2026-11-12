package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/graph"
)

type fakeBox struct {
	old        []graph.OldMessage
	before     time.Time
	max        int
	hasFolder  bool
	created    int
	moved      []string
	failMoveOf string
}

func (f *fakeBox) OldMessages(_ context.Context, _, _ string, before time.Time, max int) ([]graph.OldMessage, error) {
	f.before, f.max = before, max
	if len(f.old) > max {
		return f.old[:max], nil
	}
	return f.old, nil
}

func (f *fakeBox) FindChildFolder(context.Context, string, string, string) (graph.ChildFolder, bool, error) {
	return graph.ChildFolder{Name: "Unhandled"}, f.hasFolder, nil
}

func (f *fakeBox) CreateChildFolder(context.Context, string, string, string) (graph.ChildFolder, error) {
	f.created++
	return graph.ChildFolder{Name: "Unhandled"}, nil
}

func (f *fakeBox) MoveToChildFolder(_ context.Context, _, id string, _ graph.ChildFolder) (string, error) {
	if id == f.failMoveOf {
		return "", io.ErrUnexpectedEOF
	}
	f.moved = append(f.moved, id)
	return "new-" + id, nil
}

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func staleCfg() config.Config {
	return config.Config{GraphMailbox: "cti@example.com", GraphFolder: "inbox",
		MailboxStaleAge: 30 * 24 * time.Hour, MailboxStaleFolder: "Unhandled", MailboxStaleMax: 200}
}

var sweepNow = time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)

func oldMail() []graph.OldMessage {
	return []graph.OldMessage{
		{ID: "a", Subject: "a reported phish", ReceivedDateTime: sweepNow.AddDate(0, 0, -45)},
		{ID: "b", Subject: "flagged", ReceivedDateTime: sweepNow.AddDate(0, 0, -60), Flagged: true},
		{ID: "c", Subject: "scan notice", ReceivedDateTime: sweepNow.AddDate(0, 0, -31)},
	}
}

func TestSweepDryRunMovesNothingAndCreatesNoFolder(t *testing.T) {
	f := &fakeBox{old: oldMail()}
	var moved, failed int
	out := captureStdout(t, func() {
		_, moved, failed = sweep(context.Background(), f, staleCfg(), sweepNow, 14*24*time.Hour, false)
	})
	if moved != 0 || failed != 0 || len(f.moved) != 0 || f.created != 0 {
		t.Fatalf("a dry run moved %v / created %d folder(s)", f.moved, f.created)
	}
	if !strings.Contains(out, "STALE: would-move=2 flagged=1 folder=Unhandled") {
		t.Errorf("output lacks the STALE line:\n%s", out)
	}
	if !strings.Contains(out, "does not exist yet") {
		t.Errorf("a dry run must say the folder will be created:\n%s", out)
	}
}

func TestSweepForRealCreatesTheFolderOnceAndLeavesFlaggedMail(t *testing.T) {
	f := &fakeBox{old: oldMail()}
	var moved int
	out := captureStdout(t, func() {
		_, moved, _ = sweep(context.Background(), f, staleCfg(), sweepNow, 14*24*time.Hour, true)
	})
	if f.created != 1 || moved != 2 {
		t.Fatalf("created %d, moved %d", f.created, moved)
	}
	for _, id := range f.moved {
		if id == "b" {
			t.Error("a flagged message was swept")
		}
	}
	if !strings.Contains(out, "STALE: moved=2 flagged=1 failed=0") {
		t.Errorf("output:\n%s", out)
	}
	// The cutoff is the stale age, and the cap is passed through.
	if !f.before.Equal(sweepNow.Add(-30*24*time.Hour)) || f.max != 200 {
		t.Errorf("asked for mail before %s, max %d", f.before, f.max)
	}
}

func TestSweepCutoffFollowsAWiderWindow(t *testing.T) {
	// A --lookback 1080h catch-up plans 45 days of mail; the sweep must not
	// also take any of it.
	f := &fakeBox{hasFolder: true}
	captureStdout(t, func() {
		sweep(context.Background(), f, staleCfg(), sweepNow, 45*24*time.Hour, true)
	})
	if !f.before.Equal(sweepNow.Add(-45 * 24 * time.Hour)) {
		t.Errorf("cutoff %s, want the 45-day window", f.before)
	}
}

func TestSweepCountsAFailedMoveAndSaysWhenTheCapIsReached(t *testing.T) {
	f := &fakeBox{old: oldMail(), hasFolder: true, failMoveOf: "a"}
	cfg := staleCfg()
	cfg.MailboxStaleMax = 3
	var failed int
	out := captureStdout(t, func() {
		_, _, failed = sweep(context.Background(), f, cfg, sweepNow, 14*24*time.Hour, true)
	})
	if failed != 1 || f.created != 0 {
		t.Errorf("failed %d created %d", failed, f.created)
	}
	if !strings.Contains(out, "more remain") {
		t.Errorf("a full page must say the next run carries on:\n%s", out)
	}
}

func TestSweepOff(t *testing.T) {
	f := &fakeBox{old: oldMail()}
	cfg := staleCfg()
	cfg.MailboxStaleAge = 0
	out := captureStdout(t, func() {
		sweep(context.Background(), f, cfg, sweepNow, 14*24*time.Hour, true)
	})
	if len(f.moved) != 0 || !strings.Contains(out, "STALE: off") {
		t.Errorf("moved %v, out %q", f.moved, out)
	}
}
