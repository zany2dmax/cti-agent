// cti-podprobe reads one window of Proofpoint on Demand's Log API archive and
// prints aggregate counts: events per direction, route names, DMARC and SPF
// results, the header-From domains and DKIM data of outbound mail, and inbound
// mail that uses our domains.
//
//	cti-podprobe                       # the whole hour that began 3 hours ago
//	cti-podprobe --since 2026-11-02T10:00:00-0500 --to 2026-11-02T11:00:00-0500
//	cti-podprobe --json                # the same counts as JSON
//
// # WHAT IT IS FOR
//
// It is the first step of the domains lane's mail-gateway half (BACKLOG): it
// shows what the stream actually contains for this tenant before any lane
// depends on it. It reads and prints counts only. It never prints or stores a
// message, an address, a subject or the token, and it sends nothing.
//
// # SETTINGS
//
// POD_CLUSTER_ID and POD_API_TOKEN, from the environment or fleet.env. There
// is deliberately no flag for the token: a flag lands in shell history and in
// the process list. The token allows one session at a time (a second gets HTTP
// 409), so do not run this while another client uses the same token.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/podlog"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// client is a seam so the entry point can be tested without Proofpoint.
var client = &podlog.Client{}

// now is a seam for the window default.
var now = time.Now

const timeLayout = "2006-01-02T15:04:05-0700"

func parseTime(s string) (time.Time, error) {
	for _, l := range []string{timeLayout, time.RFC3339} {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not a time like 2026-11-02T10:00:00-0500", s)
}

func run(args []string, stdout, stderr io.Writer) int {
	fleetenv.Load()
	fs := flag.NewFlagSet("cti-podprobe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.String("since", "", "start of the window, e.g. 2026-11-02T10:00:00-0500 (default: the hour that began 3 hours ago)")
	to := fs.String("to", "", "end of the window (default: one hour after --since)")
	typ := fs.String("type", "message", "stream type: message, maillog or audit")
	topN := fs.Int("top", 20, "rows to print per table")
	asJSON := fs.Bool("json", false, "print the aggregate as JSON")
	maxBytes := fs.Int64("max-bytes", 200<<20, "stop after reading this many bytes")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	idle := fs.Duration("idle", podlog.DefaultIdle, "stop when no data arrives for this long")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	logf := func(format string, a ...any) { _, _ = fmt.Fprintf(stderr, "[podprobe] "+format+"\n", a...) }

	cluster := strings.TrimSpace(os.Getenv("POD_CLUSTER_ID"))
	token := strings.TrimSpace(os.Getenv("POD_API_TOKEN"))
	if cluster == "" || token == "" {
		logf("error  : POD_CLUSTER_ID and POD_API_TOKEN must be set (environment or fleet.env)")
		return exitErr
	}

	var start, end time.Time
	var err error
	if *since == "" {
		start = now().Add(-3 * time.Hour).Truncate(time.Hour)
	} else if start, err = parseTime(*since); err != nil {
		logf("error  : --since: %v", err)
		return exitErr
	}
	if *to == "" {
		end = start.Add(time.Hour)
	} else if end, err = parseTime(*to); err != nil {
		logf("error  : --to: %v", err)
		return exitErr
	}
	// The guide: sinceTime is used only for data older than an hour.
	if start.After(now().Add(-time.Hour)) {
		logf("error  : the window must start more than an hour ago (archive reads only)")
		return exitErr
	}
	if !end.After(start) {
		logf("error  : --to must be after --since")
		return exitErr
	}
	// Past the hour the service would turn the read into the live feed; and
	// it keeps only 30 days.
	if end.After(now().Add(-time.Hour)) {
		logf("error  : --to must be more than an hour ago (archive reads only)")
		return exitErr
	}
	if start.Before(now().Add(-30 * 24 * time.Hour)) {
		logf("error  : --since is older than the 30 days the service keeps")
		return exitErr
	}
	logf("window : %s to %s", start.Format(timeLayout), end.Format(timeLayout))

	agg := podlog.NewAggregate()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := *client
	c.IdleTimeout = *idle
	var read int64
	err = c.Stream(ctx, podlog.Params{Cluster: cluster, Token: token, Type: *typ, Since: start, To: end},
		func(msg []byte) error {
			agg.AddMessage(msg)
			read += int64(len(msg))
			if read >= *maxBytes {
				return podlog.ErrStop
			}
			return nil
		})
	switch {
	case err == nil && read >= *maxBytes:
		logf("note   : stopped at --max-bytes (%d); counts cover only part of the window", *maxBytes)
	case err == nil, errors.Is(err, io.EOF):
		logf("done   : the service ended the stream")
	case errors.Is(err, podlog.ErrDropped):
		logf("note   : the connection dropped before the service closed the stream; counts are partial")
	case errors.Is(err, podlog.ErrIdle):
		logf("note   : no data for %s; treating the window as finished", *idle)
	default:
		logf("error  : %s", safelog.Line(err.Error()))
		return exitErr
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(agg); err != nil {
			logf("error  : %v", err)
			return exitErr
		}
		return exitOK
	}
	agg.Report(stdout, *topN)
	return exitOK
}
