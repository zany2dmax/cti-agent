//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestTheLockIsTakenAndNamesItsHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "digest-daily.lock")
	if err := os.WriteFile(path, []byte("an older holder line that is longer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := open(t, path)
	var e bytes.Buffer
	if rc := lock(int(f.Fd()), 0, "pid 1, real run, started now", &e, func(time.Duration) {}, time.Now); rc != 0 {
		t.Fatalf("exit %d: %s", rc, e.String())
	}
	if b, _ := os.ReadFile(path); string(b) != "pid 1, real run, started now\n" {
		t.Fatalf("lock file = %q, want only the new holder", b)
	}
}

// A second open of the same file is a second open file description, as a
// second runner's `exec 9>>` is: it must find the lane busy.
func TestASecondRunFindsItBusyAndWaitsThenGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	first, second := open(t, path), open(t, path)
	var e bytes.Buffer
	if rc := lock(int(first.Fd()), 0, "first", &e, nil, time.Now); rc != 0 {
		t.Fatalf("first: exit %d", rc)
	}
	// Refused at once with no wait.
	if rc := lock(int(second.Fd()), 0, "second", &e, func(time.Duration) { t.Fatal("slept") }, time.Now); rc != exitBusy {
		t.Fatalf("second, no wait: exit %d", rc)
	}
	// Polls every 5s up to the wait, on a clock that moves when it sleeps.
	clock := time.Unix(0, 0)
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d); clock = clock.Add(d) }
	if rc := lock(int(second.Fd()), 12*time.Second, "second", &e, sleep, func() time.Time { return clock }); rc != exitBusy {
		t.Fatalf("second, waiting: exit %d", rc)
	}
	if len(slept) != 3 || slept[0] != 5*time.Second || slept[2] != 2*time.Second {
		t.Errorf("slept %v, want 5s 5s 2s", slept)
	}
	if b, _ := os.ReadFile(path); string(b) != "first\n" {
		t.Errorf("the waiting run overwrote the holder: %q", b)
	}
	// Once the first closes (the runner exits), the second gets it.
	_ = first.Close()
	if rc := lock(int(second.Fd()), 0, "second", &e, nil, time.Now); rc != 0 {
		t.Fatalf("after release: exit %d", rc)
	}
}

func TestBadArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"--fd", "1"}, {"--fd", "9", "--wait", "-1"}, {"--fd", "9", "x"}, {"--bogus"}} {
		var e bytes.Buffer
		if rc := run(args, &e, nil, time.Now); rc != 2 {
			t.Errorf("%v: exit %d", args, rc)
		}
	}
	var e bytes.Buffer
	if rc := run([]string{"--fd", "987", "--who", "x"}, &e, nil, time.Now); rc != 1 || !strings.Contains(e.String(), "fd 987") {
		t.Errorf("a closed descriptor: exit %d %q", rc, e.String())
	}
}
