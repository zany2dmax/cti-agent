// Package qualysrl keeps the fleet inside the Qualys API's rate and
// concurrency limits by reading the limits Qualys itself reports on every
// response, rather than by a number written into this code.
//
// # WHY HEADER-DRIVEN, NOT A CONFIGURED RATE
//
// The subscription's limits change: they go up when the contract is renewed,
// and a hard-coded "N calls per hour" is then either too slow or, after a
// downgrade, wrong in the dangerous direction. Every Qualys API response
// says where the subscription stands:
//
//	X-RateLimit-Limit           calls allowed per window
//	X-RateLimit-Window-Sec      the window, in seconds
//	X-RateLimit-Remaining       calls left in the current window
//	X-RateLimit-ToWait-Sec      seconds until the next call is allowed (0 = now)
//	X-Concurrency-Limit-Limit   calls allowed in flight at once
//	X-Concurrency-Limit-Running calls in flight now, this one included
//
// So the limiter needs no setting to follow a renewal: the next response
// carries the new numbers.
//
// # THE LIMIT IS SHARED WITH THE OTHER LANES
//
// One subscription, one budget: the VM lane, the KnowledgeBase lookups and
// the AppSec lane all spend it. Reserve is how many calls a run of THIS
// process leaves untouched for the others. Running into it is an error, not
// a wait - the optional work (a report attachment) gives way, rather than
// the daily digest finding the budget gone.
//
// # WHAT IT DOES ON A REFUSAL
//
// Qualys refuses an over-limit call with HTTP 409 (the /api/... family) or
// 429 (QPS), and says how long to wait. A refused call did nothing, so it is
// retried after that wait - when the wait is no longer than MaxWait. A longer
// wait is returned as an error naming it: an hour-long sleep inside a weekly
// run looks exactly like a hang.
package qualysrl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for the two settings. Both can be changed in fleet.env without a
// rebuild (QUALYS_RL_RESERVE, QUALYS_RL_MAX_WAIT).
const (
	DefaultReserve = 5
	DefaultMaxWait = 5 * time.Minute
	// maxAttempts bounds retries of one call that Qualys keeps refusing.
	maxAttempts = 4
)

type cleanupKey struct{}

// Cleanup marks a context for a call that removes something this process
// created - a report holding session cookies. Such a call may spend the
// reserve: leaving the report behind is worse than one call of the budget.
// It still waits out a ToWait and still gives up past MaxWait.
func Cleanup(ctx context.Context) context.Context {
	return context.WithValue(ctx, cleanupKey{}, true)
}

// ErrBudget is returned when a call would eat into the calls reserved for
// the other lanes. errors.Is it to tell "gave way on purpose" from a failure.
var ErrBudget = errors.New("qualys API budget reserved for the other lanes")

// State is the subscription's position as of the last response.
type State struct {
	Seen        bool // any rate-limit header has been read
	Limit       int  // per window; -1 unknown
	WindowSec   int
	Remaining   int // -1 unknown
	ToWaitSec   int
	ConcLimit   int // -1 unknown
	ConcRunning int
	At          time.Time
	Calls       int // calls this process made through the limiter
	Waited      time.Duration
}

// String is one log line, safe to print: numbers only.
func (s State) String() string {
	if !s.Seen {
		return fmt.Sprintf("%d call(s); Qualys sent no rate-limit headers", s.Calls)
	}
	n := func(v int) string {
		if v < 0 {
			return "?"
		}
		return strconv.Itoa(v)
	}
	out := fmt.Sprintf("%d call(s) this run; %s of %s left in a %ss window; concurrency %s/%s",
		s.Calls, n(s.Remaining), n(s.Limit), n(s.WindowSec), n(s.ConcRunning), n(s.ConcLimit))
	if s.ToWaitSec > 0 {
		out += fmt.Sprintf("; next call allowed in %ds", s.ToWaitSec)
	}
	if s.Waited > 0 {
		out += "; waited " + s.Waited.Round(time.Second).String()
	}
	return out
}

// Limiter is an http.RoundTripper. One per process per Qualys host: calls are
// serialised through it, so this process never has more than one call in
// flight and never races itself past the concurrency limit.
type Limiter struct {
	Base    http.RoundTripper
	Reserve int
	MaxWait time.Duration
	// Logf, when set, is told about every wait and the low-budget warning.
	Logf func(format string, a ...any)
	// sleep is replaced in tests.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time

	mu     sync.Mutex
	state  State
	warned bool
}

// attemptTimeout is how long one attempt may wait for response headers.
const attemptTimeout = 120 * time.Second

// New is a limiter with the settings from the environment.
func New() *Limiter {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = attemptTimeout
	l := &Limiter{Base: base, Reserve: DefaultReserve, MaxWait: DefaultMaxWait}
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("QUALYS_RL_RESERVE"))); err == nil && v >= 0 {
		l.Reserve = v
	}
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("QUALYS_RL_MAX_WAIT"))); err == nil && d >= 0 {
		l.MaxWait = d
	}
	return l
}

var (
	sharedMu sync.Mutex
	shared   = map[string]*Limiter{}
)

// Shared is the process's limiter for one Qualys host, so two clients built
// for the same subscription see one budget.
func Shared(baseURL string) *Limiter {
	key := strings.ToLower(strings.TrimRight(baseURL, "/"))
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if l, ok := shared[key]; ok {
		return l
	}
	l := New()
	shared[key] = l
	return l
}

// WaitBudget is the longest one call can spend waiting on the limiter:
// a client's overall timeout must be at least this on top of the call.
func (l *Limiter) WaitBudget() time.Duration { return l.MaxWait * (maxAttempts + 1) }

// Snapshot is the state as of the last response.
func (l *Limiter) Snapshot() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

func (l *Limiter) logf(format string, a ...any) {
	if l.Logf != nil {
		l.Logf(format, a...)
	}
}

func (l *Limiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *Limiter) pause(ctx context.Context, d time.Duration) error {
	if l.sleep != nil {
		return l.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// RoundTrip implements http.RoundTripper.
func (l *Limiter) RoundTrip(req *http.Request) (*http.Response, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx := req.Context()
	base := l.Base
	if base == nil {
		base = http.DefaultTransport
	}

	for attempt := 1; ; attempt++ {
		if err := l.beforeCall(ctx); err != nil {
			return nil, err
		}
		r := req
		if attempt > 1 {
			// A request body is consumed by the first attempt.
			if req.Body != nil && req.GetBody == nil {
				return nil, fmt.Errorf("qualys refused the call (rate limit) and its body cannot be resent")
			}
			r = req.Clone(ctx)
			if req.GetBody != nil {
				b, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				r.Body = b
			}
		}
		resp, err := base.RoundTrip(r)
		l.state.Calls++
		if err != nil {
			return nil, err
		}
		l.read(resp.Header)
		if !refused(resp) {
			l.warnIfLow()
			return resp, nil
		}
		wait := l.refusalWait()
		if attempt >= maxAttempts || wait > l.MaxWait {
			// Hand the refusal back: the caller's error message reads the
			// body, and the state is in Snapshot for the log line.
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		l.logf("qualys refused a call (HTTP %d, %s) - waiting %s, then retrying (attempt %d of %d)",
			resp.StatusCode, l.state, wait.Round(time.Second), attempt+1, maxAttempts)
		if err := l.pause(ctx, wait); err != nil {
			return nil, err
		}
		l.state.Waited += wait
		// Waited out: the window has moved, and the numbers from the refusal
		// no longer describe it. The retry's response says where it stands.
		l.state.ToWaitSec, l.state.Remaining = 0, -1
	}
}

// beforeCall waits out a ToWait the last response announced, and refuses a
// call that would spend the reserve.
func (l *Limiter) beforeCall(ctx context.Context) error {
	s := l.state
	if !s.Seen {
		return nil
	}
	// Numbers from a window that has since ended describe nothing.
	if s.WindowSec > 0 && l.clock().Sub(s.At) > time.Duration(s.WindowSec)*time.Second {
		l.state.Remaining, l.state.ToWaitSec = -1, 0
		return nil
	}
	if s.ToWaitSec > 0 {
		until := s.At.Add(time.Duration(s.ToWaitSec) * time.Second)
		if d := until.Sub(l.clock()); d > 0 {
			if d > l.MaxWait {
				return fmt.Errorf("%w: Qualys says the next call is allowed in %s, longer than "+
					"QUALYS_RL_MAX_WAIT (%s) (%s)", ErrBudget, d.Round(time.Second), l.MaxWait, s)
			}
			l.logf("qualys: waiting %s for the rate-limit window (%s)", d.Round(time.Second), s)
			if err := l.pause(ctx, d); err != nil {
				return err
			}
			l.state.Waited += d
			l.state.ToWaitSec, l.state.Remaining = 0, -1
			return nil
		}
	}
	if cleanup, _ := ctx.Value(cleanupKey{}).(bool); cleanup {
		return nil
	}
	if s.Remaining >= 0 && s.Remaining <= l.Reserve {
		return fmt.Errorf("%w: %d call(s) left in this window and QUALYS_RL_RESERVE keeps %d for "+
			"the VM lane and KnowledgeBase lookups (%s)", ErrBudget, s.Remaining, l.Reserve, s)
	}
	return nil
}

// refusalWait is how long to wait after a refused call: what Qualys said,
// else a short default, never less than a second.
func (l *Limiter) refusalWait() time.Duration {
	if l.state.ToWaitSec > 0 {
		return time.Duration(l.state.ToWaitSec) * time.Second
	}
	return 30 * time.Second
}

func (l *Limiter) warnIfLow() {
	s := l.state
	if l.warned || s.Limit <= 0 || s.Remaining < 0 {
		return
	}
	if s.Remaining*5 <= s.Limit { // 20% or less left
		l.warned = true
		l.logf("qualys: API budget is low - %s", s)
	}
}

// refused reports a response that is Qualys declining the call for rate or
// concurrency, as opposed to any other failure. A 409 alone is not enough:
// it is also an ordinary conflict on some endpoints, so a header must say
// the limit was the reason.
func refused(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusConflict:
		h := resp.Header
		// Remaining: 0 alone is not enough - the call that spent the last
		// unit can still be a genuine conflict, and retrying a create on a
		// real conflict could make a second one.
		if n, ok := header(h, "X-RateLimit-ToWait-Sec"); ok && n > 0 {
			return true
		}
		lim, ok1 := header(h, "X-Concurrency-Limit-Limit")
		run, ok2 := header(h, "X-Concurrency-Limit-Running")
		return ok1 && ok2 && lim > 0 && run > lim
	}
	return false
}

func (l *Limiter) read(h http.Header) {
	s := &l.state
	got := false
	set := func(name string, dst *int) {
		if v, ok := header(h, name); ok {
			*dst, got = v, true
		}
	}
	if !s.Seen {
		s.Limit, s.Remaining, s.ConcLimit = -1, -1, -1
	}
	toWait := 0
	set("X-RateLimit-Limit", &s.Limit)
	set("X-RateLimit-Window-Sec", &s.WindowSec)
	set("X-RateLimit-Remaining", &s.Remaining)
	set("X-RateLimit-ToWait-Sec", &toWait)
	set("X-Concurrency-Limit-Limit", &s.ConcLimit)
	set("X-Concurrency-Limit-Running", &s.ConcRunning)
	if got {
		s.Seen = true
		s.ToWaitSec = toWait
		s.At = l.clock()
	}
}

func header(h http.Header, name string) (int, bool) {
	v := strings.TrimSpace(h.Get(name))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}
