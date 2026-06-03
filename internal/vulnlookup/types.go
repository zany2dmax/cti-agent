package vulnlookup

import "context"

// DetectionSummary is the normalized vulnerability evidence returned by any backend.
type DetectionSummary struct {
	Source      string
	ExternalIDs []string
	HostCount   int
	MaxScore    int
	LastSeen    string
	Hosts       []string
}

// Result is the normalized response for a single CVE lookup.
type Result struct {
	CVE         string
	Status      string
	Source      string
	ExternalIDs []string
	HostCount   int
	MaxScore    int
	LastSeen    string
	SampleHosts []string
	Reason      string
}

// LookupProvider defines the swappable VM/EDR/backend boundary.
// Implementations can use Qualys QIDs, CrowdStrike IDs, Defender IDs, etc.,
// but callers only ask whether a CVE is present and receive normalized evidence.
type LookupProvider interface {
	Name() string
	LookupCVE(ctx context.Context, cve string) (Result, error)
}

const (
	StatusPresent    = "PRESENT"
	StatusNotPresent = "NOT_PRESENT"
	StatusUnknown    = "UNKNOWN"
)
