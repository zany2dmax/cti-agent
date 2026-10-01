package budget

import "strings"

// rateLimitMarkers are substrings that mean "the quota refused us", as opposed
// to "the command broke". The list is deliberately broad and matched
// case-insensitively: the exact wording belongs to a CLI we do not control and
// will change without warning.
//
// Erring toward over-detection is the safe direction. A false positive costs
// one skipped beat and a cooldown. A false negative means the fleet keeps
// hammering a quota its operator is trying to use, which is the entire failure
// this package exists to prevent.
// exhaustedMarkers mean the ACCOUNT is out, not that we are going too fast.
//
// THE DISTINCTION IS THE WHOLE POINT.
//
// A rate limit resolves by waiting: back off, the window resets, carry on. An
// exhausted balance does not. No backoff, however long, puts credit back on
// the account - only a person can. Treating the two alike gives you a fleet
// that retries a billing problem every thirty minutes forever.
//
// This cost six days of silence. On 24 September the real journal line was
// "Credit balance is too low", which matched none of the markers below, so
// Classify returned OutcomeError - "the script broke, fix the code". systemd
// saw exit 1, marked the unit failed, and OnFailure mailed a FAILED alert.
// The operator read "FAILED", correctly concluded the heartbeat was broken,
// and disabled the timer. Nothing then alerted, because a disabled timer
// cannot fail. The category was wrong, and the wrong category is what took
// the lane down - not the missing credit.
//
// Matched BEFORE rateLimitMarkers: a credit message may well also say
// "upgrade to", and the more specific diagnosis must win.
var exhaustedMarkers = []string{
	"credit balance is too low", // the observed wording, 2026-09-24
	"credit balance",
	"insufficient credit",
	"out of credit",
	"no credit",
	"payment required",
	"402",
	"add credits",
	"purchase more",
	"billing",
}

var rateLimitMarkers = []string{
	"rate limit",
	"rate_limit",
	"ratelimit",
	"usage limit",
	"usage_limit",
	"too many requests",
	"429",
	"quota",
	"overloaded",
	"capacity",
	"try again later",
	"upgrade to",
	"limit reached",
	"limit will reset",
	"resets at",
}

// Classify turns a claude invocation into an Outcome.
//
// Exit code alone is not enough: the CLI exits non-zero for a missing flag and
// for an exhausted quota alike, and those want opposite responses - fix the
// flag now, wait on the quota. So the text is what decides, and the exit code
// only separates success from failure.
func Classify(exitCode int, output string) Outcome {
	if exitCode == 0 {
		return OutcomeOK
	}
	lower := strings.ToLower(output)
	// Most specific first. An exhausted balance needs a person; a rate limit
	// needs patience; anything else needs a developer.
	for _, m := range exhaustedMarkers {
		if strings.Contains(lower, m) {
			return OutcomeExhausted
		}
	}
	for _, m := range rateLimitMarkers {
		if strings.Contains(lower, m) {
			return OutcomeRateLimit
		}
	}
	return OutcomeError
}
