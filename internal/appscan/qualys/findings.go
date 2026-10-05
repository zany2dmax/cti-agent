package qualys

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// API is the Qualys WAS Findings client.
//
// # SAME SUBSCRIPTION, DIFFERENT API FAMILY
//
// The VM lane talks to /api/4.0/fo/... with GET and query parameters. WAS
// talks to /qps/rest/3.0/... with POST and an XML body, on the same host with
// the same credentials. So no new secret is needed - but the service account's
// Qualys ROLE must include the WAS module, and a VM-only role fails here in a
// way that looks exactly like a bad password. authError below says which.
//
// # WHY THIS IS SEPARATE FROM Provider
//
// appscan.Provider parses a notification email and needs no credentials.
// DetailFetcher is the optional half. Keeping them apart means the counts
// still reach the weekly report when this API is down, rate-limited, or not
// licensed - the lane degrades to what the email already told us rather than
// producing nothing.
type API struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

// NewAPI builds a WAS client from the same credentials the VM lane uses.
func NewAPI(baseURL, username, password string) *API {
	return &API{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 120 * time.Second},
	}
}

// pageSize is how many findings to request per call.
//
// Qualys caps a single response and signals more with hasMoreRecords. 500 is
// comfortably under any documented limit and keeps a single application's
// backlog - which can run to four figures - to a handful of round trips.
const pageSize = 500

// maxPages bounds the pagination loop.
//
// A loop that trusts hasMoreRecords and a moving lastId is a loop that spins
// forever the day either is wrong. 40 pages is 20,000 findings, far more than
// any application here has; hitting it is a bug, and the error says so rather
// than returning a partial list that looks complete.
const maxPages = 40

// Findings returns every finding for the scan's web application.
//
// Implements appscan.DetailFetcher. since filters on last detection date; a
// zero time means no lower bound.
//
// Keyed on webApp.id whenever reconciliation against the scan list supplied
// one, and on webApp.name only as a fallback. The name this used to receive
// came from the scan TITLE ("Example Run #47" -> "Example"), which on the
// real estate matched the scanner's application name in almost no case - so
// the search returned zero findings, without error, and the report printed
// "detail not available" for nearly every application.
func (a *API) Findings(ctx context.Context, s appscan.ScanResult, since time.Time) ([]appscan.Finding, error) {
	app := s.App
	var out []appscan.Finding
	lastID := 0

	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf(
				"qualys WAS: stopped after %d pages for %q - either the "+
					"application has more findings than this lane was built for, "+
					"or pagination is not advancing. Refusing to return a partial "+
					"list that would read as complete", maxPages, app)
		}

		body, err := a.search(ctx, s, since, lastID)
		if err != nil {
			return nil, err
		}
		var resp serviceResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("qualys WAS: response is not the expected XML: %w", err)
		}
		if resp.ResponseCode != "SUCCESS" {
			return nil, fmt.Errorf("qualys WAS: %s: %s",
				resp.ResponseCode, strings.TrimSpace(resp.ResponseErrorDetails.ErrorMessage))
		}

		for _, f := range resp.Data.Findings {
			out = append(out, f.normalise())
			if f.ID > lastID {
				lastID = f.ID
			}
		}
		if !resp.HasMoreRecords {
			break
		}
		// Guard against a server that says "more" but returns nothing: that
		// combination loops forever on an unchanged lastId.
		if len(resp.Data.Findings) == 0 {
			return nil, fmt.Errorf(
				"qualys WAS: reported more records but returned none for %q", app)
		}
	}
	return out, nil
}

// search POSTs one page of the finding search.
func (a *API) search(ctx context.Context, s appscan.ScanResult, since time.Time, afterID int) ([]byte, error) {
	var crit strings.Builder
	if s.AppID != "" {
		fmt.Fprintf(&crit, `<Criteria field="webApp.id" operator="EQUALS">%s</Criteria>`,
			xmlEscape(s.AppID))
	} else {
		fmt.Fprintf(&crit, `<Criteria field="webApp.name" operator="EQUALS">%s</Criteria>`,
			xmlEscape(s.App))
	}
	// Vulnerabilities only. Verified against the live API. The report never
	// shows information-gathered or sensitive-content items, and on a real
	// application those are most of the list - the first unfiltered probe
	// returned nothing else.
	crit.WriteString(`<Criteria field="type" operator="EQUALS">VULNERABILITY</Criteria>`)
	if !since.IsZero() {
		fmt.Fprintf(&crit,
			`<Criteria field="lastDetectedDate" operator="GREATER">%s</Criteria>`,
			since.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if afterID > 0 {
		fmt.Fprintf(&crit, `<Criteria field="id" operator="GREATER">%d</Criteria>`, afterID)
	}

	payload := fmt.Sprintf(
		`<ServiceRequest><preferences><limitResults>%d</limitResults></preferences>`+
			`<filters>%s</filters></ServiceRequest>`, pageSize, crit.String())

	return a.post(ctx, "/qps/rest/3.0/search/was/finding/", payload)
}

// post sends one QPS search and returns the body of a 2xx response.
//
// Shared by every WAS search so the authentication-error explanation is in
// one place: the finding and scan searches fail identically when the role
// lacks the WAS module.
func (a *API) post(ctx context.Context, path, payload string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+path,
		strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(a.username, a.password)
	req.Header.Set("X-Requested-With", "cti-agent")
	req.Header.Set("Content-Type", "text/xml")

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qualys WAS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Qualys WAS response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, a.authError(resp.StatusCode, body)
	}
	return body, nil
}

// authError explains a non-2xx, distinguishing the failure people actually
// hit from the one they assume.
//
// A VM-only Qualys role returns 401 or 403 on every WAS endpoint while the
// identical credentials keep working for the VM lane. Reported as "qualys
// request failed: HTTP 401" that reads as a wrong password, and somebody goes
// and rotates a working secret.
func (a *API) authError(status int, body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 400 {
		trimmed = trimmed[:400] + "..."
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf(
			"qualys WAS refused the credentials (HTTP %d). These are the SAME "+
				"credentials the VM lane uses, so before rotating anything, check "+
				"that this account's Qualys role includes the WAS module - a "+
				"VM-only role fails here and nowhere else.\nresponse: %s",
			status, trimmed)
	case http.StatusTooManyRequests:
		return fmt.Errorf(
			"qualys WAS rate-limited this request (HTTP 429). The weekly report "+
				"still has the counts from the notification emails; only the "+
				"per-finding detail is missing.\nresponse: %s", trimmed)
	}
	return fmt.Errorf("qualys WAS request failed: HTTP %d: %s", status, trimmed)
}

// ─── wire format ────────────────────────────────────────────────────────────

type serviceResponse struct {
	XMLName              xml.Name `xml:"ServiceResponse"`
	ResponseCode         string   `xml:"responseCode"`
	Count                int      `xml:"count"`
	HasMoreRecords       bool     `xml:"hasMoreRecords"`
	ResponseErrorDetails struct {
		ErrorMessage string `xml:"errorMessage"`
	} `xml:"responseErrorDetails"`
	Data struct {
		Findings []wasFinding `xml:"Finding"`
	} `xml:"data"`
}

type wasFinding struct {
	ID         int    `xml:"id"`
	UniqueID   string `xml:"uniqueId"`
	QID        int    `xml:"qid"`
	Name       string `xml:"name"`
	Type       string `xml:"type"`
	Severity   int    `xml:"severity"`
	URL        string `xml:"url"`
	Status     string `xml:"status"`
	FirstFound string `xml:"firstDetectedDate"`
	LastFound  string `xml:"lastDetectedDate"`
	Param      string `xml:"param"`
	Potential  bool   `xml:"potential"`
	Ignored    bool   `xml:"isIgnored"`
}

func (f wasFinding) normalise() appscan.Finding {
	id := strconv.Itoa(f.QID)
	if f.QID == 0 {
		id = f.UniqueID
	}
	return appscan.Finding{
		ID:        id,
		Title:     strings.TrimSpace(f.Name),
		Severity:  appscan.Severity(f.Severity),
		URL:       strings.TrimSpace(f.URL),
		Param:     strings.TrimSpace(f.Param),
		Status:    strings.ToUpper(strings.TrimSpace(f.Status)),
		FirstSeen: parseQualysAPITime(f.FirstFound),
		LastSeen:  parseQualysAPITime(f.LastFound),
		Potential: f.Potential,
		Ignored:   f.Ignored,
	}
}

// parseQualysAPITime reads the ISO-8601 the QPS API emits.
//
// Deliberately NOT the same parser as the notification email, which uses
// "10/04/2026 at 00:02:43 (GMT +0000)". Two formats from one vendor is not a
// thing to paper over with a list of layouts; it is two different interfaces
// that happen to share a hostname.
func parseQualysAPITime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// xmlEscape escapes a value going into the request body.
//
// The application name comes from a scan notification, which arrives at a
// published address. An unescaped quote or angle bracket would let that text
// alter the query this code is building - the same injection shape as any
// other unescaped interpolation, just in XML.
func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}
