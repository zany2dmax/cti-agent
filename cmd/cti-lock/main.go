//go:build unix

// cti-lock takes a runner's lane lock on a file descriptor the runner holds
// open, for share/fleet-mode.sh's fleet_lock.
//
//	exec 9>>"$FLEET_HOME/state/locks/digest-daily.lock"
//	cti-lock --fd 9 --wait 600 --who "pid $$, real run, started ..."
//
// It is flock(2) on the inherited descriptor: the lock belongs to the open
// file, which the runner and everything it starts keep open until they
// exit, so the kernel releases it on any way out (kill -9 included) and
// there is never a stale lock to clear. Once it holds the lock it replaces
// the file's contents with --who, which is what another run prints when it
// finds the lane busy.
//
// It replaced a python3 snippet in fleet-mode.sh, there only because macOS
// has no flock(1). The rule is the same.
//
// # EXIT STATUS
//
//	0   the lock is held
//	75  still held by another run after --wait seconds (0: do not wait)
//	1   the descriptor cannot be locked or written
//	2   bad arguments
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const (
	exitBusy  = 75
	pollEvery = 5 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, time.Sleep, time.Now))
}

func run(args []string, stderr io.Writer, sleep func(time.Duration), now func() time.Time) int {
	fs := flag.NewFlagSet("cti-lock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fd := fs.Int("fd", -1, "the open file descriptor to lock (the runner uses 9)")
	wait := fs.Int("wait", 0, "seconds to wait for another run to let go; 0 refuses at once")
	who := fs.String("who", "", "what to write in the lock file once it is held")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || *fd < 3 || *wait < 0 {
		_, _ = fmt.Fprintln(stderr, "usage: cti-lock --fd N --wait SECONDS --who TEXT   (N is 3 or more)")
		return 2
	}
	return lock(*fd, time.Duration(*wait)*time.Second, *who, stderr, sleep, now)
}

func lock(fd int, wait time.Duration, who string, stderr io.Writer, sleep func(time.Duration), now func() time.Time) int {
	deadline := now().Add(wait)
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_, _ = fmt.Fprintf(stderr, "cti-lock: fd %d: %v\n", fd, err)
			return 1
		}
		left := deadline.Sub(now())
		if left <= 0 {
			return exitBusy
		}
		sleep(min(pollEvery, left))
	}
	if err := syscall.Ftruncate(fd, 0); err != nil {
		_, _ = fmt.Fprintf(stderr, "cti-lock: fd %d: %v\n", fd, err)
		return 1
	}
	if _, err := syscall.Write(fd, []byte(who+"\n")); err != nil {
		_, _ = fmt.Fprintf(stderr, "cti-lock: fd %d: %v\n", fd, err)
		return 1
	}
	return 0
}
