package qualysrl

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fake answers each call from a script of (status, headers).
type fake struct {
	steps  []step
	calls  int
	sent   int
	bodies []string
}

type step struct {
	status int
	h      map[string]int
}

func (f *fake) RoundTrip(r *http.Request) (*http.Response, error) {
	f.sent++
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
	}
	s := f.steps[f.calls]
	if f.calls < len(f.steps)-1 {
		f.calls++
	}
	h := http.Header{}
	for k, v := range s.h {
		h.Set(k, strconv.Itoa(v))
	}
	return &http.Response{StatusCode: s.status, Header: h, Body: io.NopCloser(strings.NewReader("x"))}, nil
}

func limiter(f *fake) (*Limiter, *[]time.Duration) {
	var slept []time.Duration
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	l := &Limiter{Base: f, Reserve: 2, MaxWait: time.Minute,
		sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); now = now.Add(d); return nil },
		now:   func() time.Time { return now }}
	return l, &slept
}

func post(t *testing.T, l *Limiter) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://qualysapi.example.com/x", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	return l.RoundTrip(req)
}

func ok(rem int) step {
	return step{200, map[string]int{"X-RateLimit-Limit": 300, "X-RateLimit-Window-Sec": 3600,
		"X-RateLimit-Remaining": rem, "X-RateLimit-ToWait-Sec": 0,
		"X-Concurrency-Limit-Limit": 2, "X-Concurrency-Limit-Running": 1}}
}

func TestReadsHeaders(t *testing.T) {
	l, _ := limiter(&fake{steps: []step{ok(250)}})
	if _, err := post(t, l); err != nil {
		t.Fatal(err)
	}
	s := l.Snapshot()
	if !s.Seen || s.Limit != 300 || s.Remaining != 250 || s.WindowSec != 3600 || s.ConcLimit != 2 || s.Calls != 1 {
		t.Fatalf("state = %+v", s)
	}
	if !strings.Contains(s.String(), "250 of 300 left") {
		t.Fatalf("String() = %q", s.String())
	}
}

func TestNoHeadersIsPassive(t *testing.T) {
	l, slept := limiter(&fake{steps: []step{{200, nil}}})
	for i := 0; i < 3; i++ {
		if _, err := post(t, l); err != nil {
			t.Fatal(err)
		}
	}
	if s := l.Snapshot(); s.Seen || s.Calls != 3 || len(*slept) != 0 {
		t.Fatalf("state = %+v slept %v", s, *slept)
	}
}

// A 429 with ToWait is waited out and the call resent with its body.
func TestRetriesRefusalAfterToWait(t *testing.T) {
	f := &fake{steps: []step{
		{429, map[string]int{"X-RateLimit-Remaining": 0, "X-RateLimit-ToWait-Sec": 20}},
		ok(299),
	}}
	l, slept := limiter(f)
	resp, err := post(t, l)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("resp %v err %v", resp, err)
	}
	if len(*slept) != 1 || (*slept)[0] != 20*time.Second {
		t.Fatalf("slept %v, want one 20s wait", *slept)
	}
	if len(f.bodies) != 2 || f.bodies[1] != "payload" {
		t.Fatalf("retry did not resend the body: %q", f.bodies)
	}
}

// The /api/... family refuses with 409; a 409 without a limit header is an
// ordinary conflict and is not retried.
func TestConflictOnlyRetriedWhenTheLimitSaysSo(t *testing.T) {
	f := &fake{steps: []step{{409, map[string]int{"X-RateLimit-ToWait-Sec": 5}}, ok(100)}}
	f3 := &fake{steps: []step{{409, map[string]int{"X-RateLimit-Remaining": 0}}, ok(100)}}
	l3, _ := limiter(f3)
	if resp, _ := post(t, l3); resp.StatusCode != 409 || f3.sent != 1 {
		t.Fatalf("409 with only Remaining 0 was retried")
	}
	l, slept := limiter(f)
	if resp, _ := post(t, l); resp.StatusCode != 200 || len(*slept) != 1 {
		t.Fatalf("rate-limit 409 not retried: %d, slept %v", resp.StatusCode, *slept)
	}
	f2 := &fake{steps: []step{{409, nil}, ok(100)}}
	l2, slept2 := limiter(f2)
	if resp, _ := post(t, l2); resp.StatusCode != 409 || len(*slept2) != 0 {
		t.Fatalf("plain 409 was retried: %d, slept %v", resp.StatusCode, *slept2)
	}
}

// A wait longer than MaxWait is handed back, not slept through.
func TestLongWaitIsNotSlept(t *testing.T) {
	f := &fake{steps: []step{{429, map[string]int{"X-RateLimit-ToWait-Sec": 1800}}}}
	l, slept := limiter(f)
	resp, err := post(t, l)
	if err != nil || resp.StatusCode != 429 || len(*slept) != 0 {
		t.Fatalf("resp %d err %v slept %v", resp.StatusCode, err, *slept)
	}
	// And the NEXT call is refused locally rather than sent.
	if _, err := post(t, l); !errors.Is(err, ErrBudget) {
		t.Fatalf("next call err = %v, want ErrBudget", err)
	}
	if f.sent != 1 {
		t.Fatalf("second call reached Qualys (%d sent)", f.sent)
	}
}

// The reserve is left for the other lanes.
func TestReserveIsNotSpent(t *testing.T) {
	f := &fake{steps: []step{ok(2)}}
	l, _ := limiter(f)
	if _, err := post(t, l); err != nil {
		t.Fatal(err)
	}
	_, err := post(t, l)
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v, want ErrBudget", err)
	}
	if !strings.Contains(err.Error(), "QUALYS_RL_RESERVE") {
		t.Fatalf("error does not name the setting: %v", err)
	}
}

// A ToWait announced on a SUCCESSFUL response is waited out before the next
// call, instead of sending it into a refusal.
func TestToWaitOnSuccessDelaysNextCall(t *testing.T) {
	s := ok(50)
	s.h["X-RateLimit-ToWait-Sec"] = 7
	f := &fake{steps: []step{s, ok(49)}}
	l, slept := limiter(f)
	for i := 0; i < 2; i++ {
		if _, err := post(t, l); err != nil {
			t.Fatal(err)
		}
	}
	if len(*slept) != 1 || (*slept)[0] != 7*time.Second {
		t.Fatalf("slept %v, want 7s", *slept)
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	f := &fake{steps: []step{{429, map[string]int{"X-RateLimit-ToWait-Sec": 1}}}}
	l, slept := limiter(f)
	resp, err := post(t, l)
	if err != nil || resp.StatusCode != 429 {
		t.Fatalf("resp %v err %v", resp, err)
	}
	if len(*slept) != maxAttempts-1 {
		t.Fatalf("slept %d times, want %d", len(*slept), maxAttempts-1)
	}
}

// A cleanup call may spend the reserve; nothing else may.
func TestCleanupSpendsTheReserve(t *testing.T) {
	f := &fake{steps: []step{ok(1), ok(0)}}
	l, _ := limiter(f)
	if _, err := post(t, l); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(Cleanup(context.Background()), http.MethodPost,
		"https://qualysapi.example.com/delete", strings.NewReader("x"))
	if _, err := l.RoundTrip(req); err != nil {
		t.Fatalf("cleanup refused: %v", err)
	}
}

// After the window has passed, an exhausted reserve no longer blocks.
func TestStateExpiresWithItsWindow(t *testing.T) {
	f := &fake{steps: []step{ok(1), ok(299)}}
	l, slept := limiter(f)
	if _, err := post(t, l); err != nil {
		t.Fatal(err)
	}
	if _, err := post(t, l); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v", err)
	}
	_ = l.pause(context.Background(), 3601*time.Second) // advance the fake clock
	*slept = nil
	if _, err := post(t, l); err != nil {
		t.Fatalf("new window still refused: %v", err)
	}
}

func TestEnvSettings(t *testing.T) {
	t.Setenv("QUALYS_RL_RESERVE", "20")
	t.Setenv("QUALYS_RL_MAX_WAIT", "90s")
	l := New()
	if l.Reserve != 20 || l.MaxWait != 90*time.Second {
		t.Fatalf("reserve %d maxwait %s", l.Reserve, l.MaxWait)
	}
	t.Setenv("QUALYS_RL_RESERVE", "nonsense")
	if New().Reserve != DefaultReserve {
		t.Fatal("bad value not ignored")
	}
}

func TestSharedIsPerHost(t *testing.T) {
	a := Shared("https://qualysapi.example.com/")
	if Shared("https://QUALYSAPI.example.com") != a {
		t.Fatal("same host, different limiter")
	}
	if Shared("https://qualysapi.other.example.com") == a {
		t.Fatal("different hosts share a limiter")
	}
}
