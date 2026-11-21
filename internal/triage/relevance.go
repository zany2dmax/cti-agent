package triage

// Relevance values: the judge's verdict on one subject (judge.go). Anything
// else is replaced with RelevanceUnknown, because a relevance this code does
// not recognise cannot be sorted, coloured or reasoned about, and silently
// treating it as "unlikely" would be the worst available guess.
const (
	RelevanceLikely   = "likely"
	RelevancePossible = "possible"
	RelevanceUnlikely = "unlikely"
	RelevanceUnknown  = "unknown"
)

// rank orders the digest: the things a person should look at first come first.
// Unknown sorts above unlikely because "we could not tell" deserves more of a
// reader's attention than "we checked and it does not apply".
func rank(relevance string) int {
	switch relevance {
	case RelevanceLikely:
		return 0
	case RelevancePossible:
		return 1
	case RelevanceUnknown:
		return 2
	default:
		return 3
	}
}
