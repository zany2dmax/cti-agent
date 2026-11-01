package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

func writeTicketsFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "tickets.json")
	tk := appTicket(xss("https://app.example.com/a?x=SLEEP(1)"))
	if err := os.WriteFile(path, appscan.TicketsFile{Tickets: []appscan.AppTicket{tk}}.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func init() { probePause = 0 }

// gateway refuses any comment containing one of the needles, as a firewall
// would, and counts what it was sent.
type gateway struct {
	needles []string
	sent    []string
	// refuseOver refuses a comment of more than this many characters (0: none)
	refuseOver int
}

func (g *gateway) post(_ context.Context, _ string, text string) error {
	g.sent = append(g.sent, text)
	for _, n := range g.needles {
		if strings.Contains(text, n) {
			return errors.New("HTTP 403: ERROR: The request could not be satisfied")
		}
	}
	if g.refuseOver > 0 && len(text) > g.refuseOver {
		return errors.New("HTTP 403: too big")
	}
	return nil
}

func lines(n int, bad map[int]string) string {
	var out []string
	for i := 1; i <= n; i++ {
		if s, ok := bad[i]; ok {
			out = append(out, s)
		} else {
			out = append(out, "ordinary line "+strings.Repeat("x", i%7))
		}
	}
	return strings.Join(out, "\n")
}

func TestProbeNamesTheRefusedLines(t *testing.T) {
	g := &gateway{needles: []string{"SLEEP(", "forName("}}
	text := lines(120, map[int]string{17: "payload SELECT SLEEP(29) here", 88: "x.getClass().forName('r')"})
	p := &probe{post: g.post, key: "T-1"}
	verdict, pieces := p.run(context.Background(), text)
	if !strings.Contains(verdict, "narrowed by line") {
		t.Fatalf("verdict = %q", verdict)
	}
	if len(pieces) != 2 || pieces[0].First != 17 || pieces[1].First != 88 || pieces[0].Together || pieces[1].Together {
		t.Fatalf("pieces = %+v", pieces)
	}
	if p.posted > 2+2*2*8 { // control, whole, then both halves at each of ~7 levels, per culprit
		t.Errorf("%d posts for two culprits in 120 lines", p.posted)
	}
}

func TestProbeAcceptedWholeSaysSo(t *testing.T) {
	g := &gateway{}
	p := &probe{post: g.post, key: "T-1"}
	verdict, pieces := p.run(context.Background(), lines(10, nil))
	if len(pieces) != 0 || !strings.Contains(verdict, "ACCEPTED") {
		t.Fatalf("verdict %q pieces %+v", verdict, pieces)
	}
}

// A refusal that no single half reproduces (size, or two lines together) is
// reported as a group, never blamed on one line.
func TestProbeReportsAGroupWhenOnlyTheWholeIsRefused(t *testing.T) {
	g := &gateway{refuseOver: 400}
	p := &probe{post: g.post, key: "T-1"}
	_, pieces := p.run(context.Background(), lines(60, nil))
	if len(pieces) == 0 {
		t.Fatal("a size refusal was not reported")
	}
	for _, pc := range pieces {
		if !pc.Together {
			t.Fatalf("a size limit was blamed on one line: %+v", pc)
		}
	}
}

func TestProbeStopsWhenEvenAPlainCommentIsRefused(t *testing.T) {
	g := &gateway{needles: []string{"control"}}
	p := &probe{post: g.post, key: "T-1"}
	verdict, pieces := p.run(context.Background(), lines(10, nil))
	if len(pieces) != 0 || !strings.Contains(verdict, "plain one-line comment was refused") || len(g.sent) != 1 {
		t.Fatalf("verdict %q pieces %+v sent %d", verdict, pieces, len(g.sent))
	}
}

func TestProbeNeverExceedsItsPostBudget(t *testing.T) {
	g := &gateway{needles: []string{"ordinary"}} // every line is refused
	p := &probe{post: g.post, key: "T-1"}
	_, pieces := p.run(context.Background(), lines(500, nil))
	if len(g.sent) > probeMaxPosts {
		t.Fatalf("posted %d comments, budget %d", len(g.sent), probeMaxPosts)
	}
	if len(pieces) == 0 {
		t.Fatal("no result reported")
	}
}

// Through the entry point: a preview posts nothing, and the probe refuses any
// ticket that is not an --appscan-test one.
func TestCommentProbePreviewPostsNothingAndGuardsTheTicket(t *testing.T) {
	dir := t.TempDir()
	path := writeTicketsFile(t, dir)
	fj, c := newFakeJira(t)
	if rc := doAppscanCommentProbe(context.Background(), c, testCfg, path, "101", "SEC-9", false, time.Now()); rc != exitOK {
		t.Fatalf("preview rc = %d", rc)
	}
	if len(fj.comments) != 0 {
		t.Fatalf("a preview posted %v", fj.comments)
	}
	// The fake's search returns no issues: not a labelled test ticket.
	if rc := doAppscanCommentProbe(context.Background(), c, testCfg, path, "101", "SEC-9", true, time.Now()); rc == exitOK {
		t.Fatal("probe commented on a ticket that is not a labelled test ticket")
	}
	if len(fj.comments) != 0 {
		t.Fatalf("posted to an unlabelled ticket: %v", fj.comments)
	}
	// A weekly-run ticket (carries cti-agent-appscan) is refused even with the test label.
	weekly := ticket("SEC-9", "CVE-2026-1", "indeterminate")
	weekly["fields"].(map[string]any)["labels"] = []string{appscanTestLabel, appscanLabel}
	fj2, c2 := newFakeJira(t, weekly)
	if rc := doAppscanCommentProbe(context.Background(), c2, testCfg, path, "101", "SEC-9", true, time.Now()); rc == exitOK || len(fj2.comments) != 0 {
		t.Fatalf("commented on a weekly-run ticket: rc=%d %v", rc, fj2.comments)
	}
	// A real test ticket works end to end: control + whole comment accepted.
	ok := ticket("SEC-9", "CVE-2026-1", "indeterminate")
	ok["fields"].(map[string]any)["labels"] = []string{appscanTestLabel}
	fj3, c3 := newFakeJira(t, ok)
	if rc := doAppscanCommentProbe(context.Background(), c3, testCfg, path, "101", "SEC-9", true, time.Now()); rc != exitOK {
		t.Fatalf("probe rc = %d", rc)
	}
	if n := len(fj3.comments["SEC-9"]); n != 2 {
		t.Fatalf("posted %d comments, want control + whole", n)
	}
}
