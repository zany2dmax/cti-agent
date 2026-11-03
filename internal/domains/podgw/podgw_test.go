package podgw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/podlog"
)

type fake struct {
	msgs []string
	err  error
	got  podlog.Params
}

func (f *fake) Stream(_ context.Context, p podlog.Params, fn func([]byte) error) error {
	f.got = p
	for _, m := range f.msgs {
		if err := fn([]byte(m)); err != nil {
			if errors.Is(err, podlog.ErrStop) {
				return nil
			}
			return err
		}
	}
	return f.err
}

// All names and addresses are invented.
const (
	outEv = `{"connection":{"ip":"192.0.2.1"},"msg":{"parsedAddresses":{"from":["a@example.com"]}},` +
		`"filter":{"qid":"1","routes":["allow_relay"],"routeDirection":"outbound","modules":{}}}`
	spoofPass = `{"connection":{"ip":"192.0.2.2"},"msg":{"parsedAddresses":{"from":["b@example.com"]}},` +
		`"filter":{"qid":"2","routes":["mydomains_from_hdr"],"routeDirection":"inbound",` +
		`"modules":{"dmarc":{"filterdResult":"pass"}}}}`
	spoofFail = `{"connection":{"ip":"192.0.2.3"},"msg":{"parsedAddresses":{"from":["c@example.com"]}},` +
		`"filter":{"qid":"3","routes":["mydomains_from_hdr"],"routeDirection":"inbound",` +
		`"modules":{"dmarc":{"filterdResult":"fail"}}}}`
)

var since = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// withTS puts an event time inside the window.
func withTS(ev, ts string) string { return `{"ts":"` + ts + `",` + ev[1:] }

func read(t *testing.T, f *fake, max int64) (ev struct {
	complete bool
	reason   string
	events   int
	out      int
	inTotal  int
	inPass   int
}, err error) {
	t.Helper()
	g := &Gateway{Source: f, Cluster: "example_hosted", Token: "tok", MaxBytes: max}
	e, err := g.Evidence(context.Background(), since, since.Add(24*time.Hour))
	ev.complete, ev.reason, ev.events = e.Complete, e.Reason, e.Events
	ev.out = e.Outbound["example.com"]
	ev.inTotal, ev.inPass = e.Inbound["example.com"].Total, e.Inbound["example.com"].Pass
	return ev, err
}

func TestCompleteReadCountsOutboundAndInbound(t *testing.T) {
	f := &fake{msgs: []string{withTS(outEv, "2026-11-01T00:30:00.000000+0000"), outEv,
		spoofPass, withTS(spoofFail, "2026-11-01T23:30:00.000000+0000")}, err: io.EOF}
	ev, err := read(t, f, 0)
	if err != nil || !ev.complete || ev.events != 4 || ev.out != 2 || ev.inTotal != 2 || ev.inPass != 1 {
		t.Fatalf("%+v err=%v", ev, err)
	}
	if f.got.Type != "message" || f.got.Cluster != "example_hosted" || !f.got.Since.Equal(since) {
		t.Errorf("params: %+v", f.got)
	}
}

func TestIncompleteReadsAreNeverComplete(t *testing.T) {
	cases := map[string]*fake{
		"idle":      {msgs: []string{outEv}, err: podlog.ErrIdle},
		"dropped":   {msgs: []string{outEv}, err: podlog.ErrDropped},
		"too early": {msgs: []string{withTS(outEv, "2026-11-01T00:10:00.000000+0000")}, err: io.EOF},
		"undecoded": {msgs: []string{outEv, "not json"}, err: io.EOF},
		"empty":     {err: io.EOF},
	}
	for name, f := range cases {
		ev, err := read(t, f, 0)
		if err != nil || ev.complete || ev.reason == "" {
			t.Errorf("%s: %+v err=%v", name, ev, err)
		}
	}
	ev, err := read(t, &fake{msgs: []string{outEv, outEv}, err: io.EOF}, 10)
	if err != nil || ev.complete || !strings.Contains(ev.reason, "cap") {
		t.Errorf("cap: %+v err=%v", ev, err)
	}
}

func TestHardErrorIsReturned(t *testing.T) {
	_, err := read(t, &fake{err: &podlog.StatusError{Code: 409, Status: "409 Conflict"}}, 0)
	if err == nil || !strings.Contains(err.Error(), "another session") {
		t.Fatalf("err = %v", err)
	}
}

func TestOverflowOfSenderDomainsIsIncomplete(t *testing.T) {
	var msgs []string
	msgs = append(msgs, withTS(outEv, "2026-11-01T00:10:00.000000+0000"), withTS(outEv, "2026-11-01T23:50:00.000000+0000"))
	for i := 0; i < podlog.MaxKeys+5; i++ {
		msgs = append(msgs, strings.Replace(outEv, "a@example.com", fmt.Sprintf("a@d%d.example", i), 1))
	}
	ev, err := read(t, &fake{msgs: msgs, err: io.EOF}, 0)
	if err != nil || ev.complete || !strings.Contains(ev.reason, "more distinct sender domains") {
		t.Fatalf("%+v err=%v", ev, err)
	}
}
