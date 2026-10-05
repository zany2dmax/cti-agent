package qualys

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Scan is one row of the Qualys WAS scan list.
//
// Built against a real search/was/wasscan response, not the documentation:
// the field names below are the elements that response carried. The
// <verbose> preference this was first probed with does not exist in the
// schema and was rejected as INVALID_XML, which is the argument for doing it
// this way round.
type Scan struct {
	ID        int
	Name      string // the run's title, e.g. "<app> Run #48"
	Reference string // "was/1700000000000.10000000" - the key the email also carries

	// Type is VULNERABILITY or DISCOVERY. A discovery scan crawls and tests
	// nothing, so it is never a vulnerability result.
	Type string
	// Mode is SCHEDULED or ONDEMAND.
	Mode string

	WebAppID   string
	WebAppName string // trimmed and whitespace-collapsed; the raw value has trailing spaces
	WebAppURL  string

	// AuthRecord is the configured credential set's name, empty when none.
	AuthRecord string

	Launched time.Time
	// Status is FINISHED, RUNNING, CANCELED, ... verbatim.
	Status string

	// From <summary>, which is ABSENT on a cancelled or running scan. Zero
	// and empty then mean "not reported", not "none".
	LinksCrawled  int
	ResultsStatus string // SUCCESSFUL, ...
	AuthStatus    string // NONE, SUCCESSFUL, FAILED
}

// InFlight reports a scan that has not finished one way or the other.
//
// Not a fault and not a result: it will appear, finished, in a later run. The
// list is the statuses that mean "not yet", rather than the ones that mean
// "done", so a status this code has never seen is treated as terminal and
// surfaces somewhere instead of being skipped for ever.
func (s Scan) InFlight() bool {
	switch strings.ToUpper(s.Status) {
	case "SUBMITTED", "RUNNING", "PROCESSING":
		return true
	}
	return false
}

// Complete reports a scan whose results describe a finished measurement.
func (s Scan) Complete() bool {
	if !strings.EqualFold(s.Status, "FINISHED") {
		return false
	}
	return s.ResultsStatus == "" || strings.EqualFold(s.ResultsStatus, "SUCCESSFUL")
}

// scanPageSize and scanMaxPages bound the listing the same way the finding
// search is bounded: 200 a page, 20 pages. A real fortnight here is about
// twenty scans, so hitting the cap is a bug or a runaway, and is reported as
// one rather than returned as a list that looks complete.
const (
	scanPageSize = 200
	scanMaxPages = 20
)

// Scans returns every WAS scan launched after since, oldest first.
//
// Read-only: one search endpoint. Nothing here launches, cancels or edits a
// scan, and the account needs no more than read access to WAS.
func (a *API) Scans(ctx context.Context, since time.Time) ([]Scan, error) {
	var out []Scan
	lastID := 0
	for page := 0; ; page++ {
		if page >= scanMaxPages {
			return nil, fmt.Errorf(
				"qualys WAS: scan list stopped after %d pages - either far more "+
					"scans than this lane was built for, or pagination is not "+
					"advancing. Refusing to return a partial list that would read "+
					"as complete", scanMaxPages)
		}
		body, err := a.post(ctx, "/qps/rest/3.0/search/was/wasscan", scanQuery(since, lastID))
		if err != nil {
			return nil, err
		}
		got, more, err := parseScans(body)
		if err != nil {
			return nil, err
		}
		for _, s := range got {
			out = append(out, s)
			if s.ID > lastID {
				lastID = s.ID
			}
		}
		if !more {
			break
		}
		if len(got) == 0 {
			return nil, fmt.Errorf("qualys WAS: scan list reported more records but returned none")
		}
	}
	return out, nil
}

// scanQuery is one page of the scan search.
//
// Preferences carry limitResults only. The schema is strict and ORDERED
// (limitResults, then startFromId or startFromOffset); an element it does not
// expect fails the whole request as INVALID_XML. Paging is by id criteria
// instead, the same mechanism the finding search already uses.
func scanQuery(since time.Time, afterID int) string {
	var crit strings.Builder
	if !since.IsZero() {
		fmt.Fprintf(&crit, `<Criteria field="launchedDate" operator="GREATER">%s</Criteria>`,
			since.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if afterID > 0 {
		fmt.Fprintf(&crit, `<Criteria field="id" operator="GREATER">%d</Criteria>`, afterID)
	}
	return fmt.Sprintf(`<ServiceRequest><preferences><limitResults>%d</limitResults>`+
		`</preferences><filters>%s</filters></ServiceRequest>`, scanPageSize, crit.String())
}

// parseScans decodes one response page.
func parseScans(body []byte) ([]Scan, bool, error) {
	var resp struct {
		XMLName              xml.Name `xml:"ServiceResponse"`
		ResponseCode         string   `xml:"responseCode"`
		HasMoreRecords       bool     `xml:"hasMoreRecords"`
		ResponseErrorDetails struct {
			ErrorMessage string `xml:"errorMessage"`
		} `xml:"responseErrorDetails"`
		Data struct {
			Scans []wasScan `xml:"WasScan"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, false, fmt.Errorf("qualys WAS: scan list is not the expected XML: %w", err)
	}
	if resp.ResponseCode != "SUCCESS" {
		return nil, false, fmt.Errorf("qualys WAS: scan list: %s: %s", resp.ResponseCode,
			strings.TrimSpace(resp.ResponseErrorDetails.ErrorMessage))
	}
	out := make([]Scan, 0, len(resp.Data.Scans))
	for _, w := range resp.Data.Scans {
		out = append(out, w.normalise())
	}
	return out, resp.HasMoreRecords, nil
}

type wasScan struct {
	ID        int    `xml:"id"`
	Name      string `xml:"name"`
	Reference string `xml:"reference"`
	Type      string `xml:"type"`
	Mode      string `xml:"mode"`
	Target    struct {
		WebApp struct {
			ID   string `xml:"id"`
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"webApp"`
		AuthRecord struct {
			Name string `xml:"name"`
		} `xml:"webAppAuthRecord"`
	} `xml:"target"`
	LaunchedDate string `xml:"launchedDate"`
	Status       string `xml:"status"`
	Summary      struct {
		LinksCrawled  int    `xml:"linksCrawled"`
		ResultsStatus string `xml:"resultsStatus"`
		AuthStatus    string `xml:"authStatus"`
	} `xml:"summary"`
}

func (w wasScan) normalise() Scan {
	return Scan{
		ID:            w.ID,
		Name:          tidy(w.Name),
		Reference:     strings.TrimSpace(w.Reference),
		Type:          strings.ToUpper(strings.TrimSpace(w.Type)),
		Mode:          strings.ToUpper(strings.TrimSpace(w.Mode)),
		WebAppID:      strings.TrimSpace(w.Target.WebApp.ID),
		WebAppName:    tidy(w.Target.WebApp.Name),
		WebAppURL:     strings.TrimSpace(w.Target.WebApp.URL),
		AuthRecord:    tidy(w.Target.AuthRecord.Name),
		Launched:      parseQualysAPITime(w.LaunchedDate),
		Status:        strings.ToUpper(strings.TrimSpace(w.Status)),
		LinksCrawled:  w.Summary.LinksCrawled,
		ResultsStatus: strings.ToUpper(strings.TrimSpace(w.Summary.ResultsStatus)),
		AuthStatus:    strings.ToUpper(strings.TrimSpace(w.Summary.AuthStatus)),
	}
}

// tidy trims and collapses internal runs of whitespace.
//
// Real application names and titles arrive with trailing spaces and doubled
// spaces inside them. Left alone, the same application keyed by name becomes
// two applications, and a report column aligned on the name drifts.
func tidy(s string) string { return strings.Join(strings.Fields(s), " ") }
