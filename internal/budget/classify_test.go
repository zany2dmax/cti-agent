package budget

import "testing"

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
