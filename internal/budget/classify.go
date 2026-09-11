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
	for _, m := range rateLimitMarkers {
		if strings.Contains(lower, m) {
			return OutcomeRateLimit
		}
	}
	return OutcomeError
}
