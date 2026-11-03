// Package podgw is the Proofpoint on Demand implementation of
// domains.MailGateway: one archive read of the Log API, reduced to counts by
// internal/podlog. See RUNBOOK 11g section 7 for what the fleet relies on.
package podgw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zany2dmax/cti-agent/internal/domains"
	"github.com/zany2dmax/cti-agent/internal/podlog"
)

// DefaultMaxBytes stops a runaway read. A business hour is about 70 MB, so a
// week is a few GB; 20 GB is well above any real week and still a bound.
const DefaultMaxBytes = 20 << 30

// coverageMargin is how far inside the window the first and last event may
// fall. Mail never stops for hours at a time, so a gap this large at either end
// means the service did not serve it.
const coverageMargin = 3 * time.Hour

// Streamer is what the gateway needs from podlog.Client; a test supplies its
// own.
type Streamer interface {
	Stream(ctx context.Context, p podlog.Params, fn func(msg []byte) error) error
}

// Gateway reads the Log API for one cluster.
type Gateway struct {
	Source   Streamer // nil: a production podlog.Client
	Cluster  string
	Token    string
	MaxBytes int64
}

// Name is for the report.
func (g *Gateway) Name() string { return "Proofpoint on Demand" }

// Evidence makes ONE connection (the token allows one session at a time, and
// the guide forbids polling) and reads the whole window.
func (g *Gateway) Evidence(ctx context.Context, since, to time.Time) (domains.GatewayEvidence, error) {
	ev := domains.GatewayEvidence{Gateway: g.Name(), Since: since, To: to}
	var c Streamer = &podlog.Client{}
	if g.Source != nil {
		c = g.Source
	}
	limit := g.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxBytes
	}
	agg := podlog.NewAggregate()
	var read int64
	capped := false
	err := c.Stream(ctx, podlog.Params{Cluster: g.Cluster, Token: g.Token, Type: "message", Since: since, To: to},
		func(msg []byte) error {
			agg.AddMessage(msg)
			read += int64(len(msg))
			if read >= limit {
				capped = true
				return podlog.ErrStop
			}
			return nil
		})

	ev.Events = agg.Events
	ev.Unattributed = agg.OutboundUnattributed
	ev.Outbound = map[string]int{}
	for k, v := range agg.OutboundFrom {
		ev.Outbound[k] = v
	}
	ev.Inbound = map[string]domains.InboundClaim{}
	for k, st := range agg.Spoof {
		ev.Inbound[k] = domains.InboundClaim{Total: st.Total, Pass: st.DMARC["pass"]}
	}

	first, last := agg.Span()
	switch {
	case capped:
		ev.Reason = fmt.Sprintf("the read stopped at the %d-byte cap", limit)
	case errors.Is(err, podlog.ErrIdle):
		ev.Reason = "the stream went quiet before the service closed it"
	case errors.Is(err, podlog.ErrDropped):
		// Not a close frame: the network or the service cut the connection, and
		// everything after the cut is missing. That is the case that could
		// lock down a domain which only sent mail late in the window.
		ev.Reason = "the connection dropped before the service closed the stream"
	case err != nil && !errors.Is(err, io.EOF):
		return ev, err
	case agg.OutboundFrom[podlog.OverflowKey] > 0:
		// Past the distinct-domain cap, senders are pooled and unnamed; a real
		// sender could be one of them.
		ev.Reason = "more distinct sender domains than the aggregate can name"
	case agg.Undecoded > 0:
		// One unreadable message could be the one outbound message that
		// proves a domain sends.
		ev.Reason = fmt.Sprintf("%d message(s) could not be decoded", agg.Undecoded)
	case agg.Events == 0:
		ev.Reason = "the window held no events, so it proves nothing"
	case first.After(since.Add(coverageMargin)) || last.Before(to.Add(-coverageMargin)):
		// A clean close that still left the start or end of the window empty
		// means the service served less than was asked for.
		ev.Reason = fmt.Sprintf("the events cover %s to %s UTC, not the whole window",
			first.UTC().Format("2006-01-02 15:04"), last.UTC().Format("2006-01-02 15:04"))
	default:
		ev.Complete = true
	}
	return ev, nil
}
