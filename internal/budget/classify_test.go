package budget

import (
	"testing"
	"time"
)

func TestClassifySuccessIgnoresOutputEntirely(t *testing.T) {
	// A successful beat that happened to discuss rate limits in its own output
	// is not a rate limit. Exit 0 settles it.
	if got := Classify(0, "we should discuss the 429 rate limit policy"); got != OutcomeOK {
		t.Errorf("got %s, want ok", got)
	}
}

func TestClassifyRecognisesQuotaRefusals(t *testing.T) {
	for _, out := range []string{
		"Error: rate limit exceeded",
		"RATE_LIMIT_ERROR",
		"429 Too Many Requests",
		"You've reached your usage limit for this 5-hour window",
		"Claude usage limit reached. Your limit will reset at 3pm",
		"API error: overloaded_error",
		"quota exhausted",
		"Please try again later",
		"upgrade to Max for higher limits",
	} {
		if got := Classify(1, out); got != OutcomeRateLimit {
			t.Errorf("Classify(%q) = %s, want ratelimit", out, got)
		}
	}
}

func TestClassifySeparatesBreakageFromThrottling(t *testing.T) {
	// These want opposite responses: fix the flag now, wait on the quota.
	for _, out := range []string{
		"unknown flag: --nope",
		"permission denied",
		"CLAUDE.md not found",
		"",
	} {
		if got := Classify(1, out); got != OutcomeError {
			t.Errorf("Classify(%q) = %s, want error", out, got)
		}
	}
}

func TestClassifyIsCaseInsensitive(t *testing.T) {
	// The wording belongs to a CLI we do not control.
	if got := Classify(1, "RATE LIMIT EXCEEDED"); got != OutcomeRateLimit {
		t.Errorf("got %s, want ratelimit", got)
	}
}

// ─── the 24 September outage, as a test ─────────────────────────────────────

func TestTheRealCreditExhaustionLineIsNotAScriptError(t *testing.T) {
	// Verbatim from the journal, crscvmtest01, 2026-09-24 15:52:21. Classified
	// as OutcomeError, which told systemd the lane was broken, which produced
	// a FAILED alert, which got the timer disabled for six days.
	got := Classify(1, "Credit balance is too low")
	if got != OutcomeExhausted {
		t.Fatalf("Classify = %q, want %q - this exact string cost six days of silence",
			got, OutcomeExhausted)
	}
	if !got.NeedsAPerson() {
		t.Error("an exhausted balance must be flagged as needing a person")
	}
	if got.Charges() {
		t.Error("an exhausted balance must not consume quota it never spent")
	}
}

func TestExhaustionIsNotConfusedWithThrottling(t *testing.T) {
	// The two need opposite responses: wait, versus go and pay. A test that
	// only checked "not OutcomeError" would pass with both mapped to
	// ratelimit, which is the mistake that looks like a fix.
	for _, out := range []string{
		"Credit balance is too low",
		"credit balance too low, please add credits",
		"Insufficient credit on this account",
		"402 Payment Required",
		"Your billing account needs attention",
	} {
		if got := Classify(1, out); got != OutcomeExhausted {
			t.Errorf("Classify(%q) = %q, want exhausted", out, got)
		}
	}
	for _, out := range []string{
		"Rate limit exceeded",
		"429 Too Many Requests",
		"usage limit reached, resets at 15:00",
		"API is overloaded, try again later",
	} {
		if got := Classify(1, out); got != OutcomeRateLimit {
			t.Errorf("Classify(%q) = %q, want ratelimit", out, got)
		}
	}
	for _, out := range []string{
		"unknown flag: --permission-mode",
		"no such file or directory",
		"",
	} {
		if got := Classify(1, out); got != OutcomeError {
			t.Errorf("Classify(%q) = %q, want error", out, got)
		}
	}
}

func TestExhaustionGoesStraightToTheLongestBackoff(t *testing.T) {
	// The exponential ramp assumes waiting helps. Here it does not, so
	// starting at 30 minutes just buys a dozen pointless retries.
	s, _ := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeExhausted, "credit")
	want := s.Now().Add(s.Limits.BackoffMax)
	if !l.CooldownUntil.Equal(want) {
		t.Errorf("CooldownUntil = %s, want %s (BackoffMax, not BackoffBase)",
			l.CooldownUntil.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}
