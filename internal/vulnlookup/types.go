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

	// HostCount is the number of distinct MACHINES affected: the union across
	// this CVE's detection IDs, not the sum of their host counts. A CVE
	// routinely maps to several QIDs for the same cumulative update, and
	// summing counted the same machine once per QID.
	HostCount int
	// HostCountIsFloor means the provider truncated its host lists, so the
	// union is a lower bound. Anything printing HostCount has to say "at
	// least" when this is set, or it is reporting a floor as a measurement.
	HostCountIsFloor bool
	// Detections is the number of open detections - roughly QID-by-host pairs.
	// Kept distinct from HostCount because "1234 detections" and "1234
	// machines" are wildly different facts and the old code produced one
	// number that was quietly used as both.
	Detections int

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
