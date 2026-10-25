package qualys

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/qualysrl"
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
	// limiter reads the rate-limit headers on every response; shared by
	// every client in the process for the same Qualys host.
	limiter        *qualysrl.Limiter
	reportTemplate string
}

// NewAPI builds a WAS client from the same credentials the VM lane uses.
func NewAPI(baseURL, username, password string) *API {
	l := qualysrl.Shared(baseURL)
	if l.Logf == nil {
		l.Logf = warnf
	}
	return &API{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		// The overall timeout has to cover the limiter's own waits, or a
		// five-minute rate-limit wait dies at two minutes looking like a
		// network fault. A hung server is still caught per attempt, by the
		// limiter's transport (ResponseHeaderTimeout).
		http:    &http.Client{Timeout: 120*time.Second + l.WaitBudget(), Transport: l},
		limiter: l,
	}
}

// warnf is where the client's own warnings go: stderr, which every command
// sends to the journal. Numbers and Qualys ids only - never a credential.
func warnf(format string, a ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "[qualys] "+format+"\n", a...)
}

func (a *API) warnf(format string, a2 ...any) { warnf(format, a2...) }

// pageSize is how many findings to request per call.
//
// Qualys caps a single response and signals more with hasMoreRecords. 500 is
// comfortably under any documented limit and keeps a single application's
// backlog - which can run to four figures - to a handful of round trips.
const pageSize = 500

// verbosePageSize pages the verbose open-findings search, whose records
// carry request and response evidence and run to kilobytes each.
const verbosePageSize = 100

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
	return a.findings(ctx, s, since, false)
}

// OpenFindings returns every finding the scanner still holds open for the
// application - NEW, ACTIVE or REOPENED - however long ago it was last
// detected.
//
// THIS, NOT Findings, IS WHAT A TICKET IS BUILT FROM. Findings filters on
// "last detected this week", which is right for "what changed" and wrong for
// "what is open": a finding the week's scan did not re-test (a page it did
// not reach, a scan without the login) drops out of that window while
// Qualys still has it open, and a ticket built from it would be told the
// finding was fixed. Qualys marks a finding FIXED only after a retest.
func (a *API) OpenFindings(ctx context.Context, s appscan.ScanResult) ([]appscan.Finding, error) {
	return a.findings(ctx, s, time.Time{}, true)
}

func (a *API) findings(ctx context.Context, s appscan.ScanResult, since time.Time, open bool) ([]appscan.Finding, error) {
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

		body, err := a.search(ctx, s, since, lastID, open)
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
func (a *API) search(ctx context.Context, s appscan.ScanResult, since time.Time, afterID int, open bool) ([]byte, error) {
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
	if open {
		crit.WriteString(`<Criteria field="status" operator="IN">NEW,ACTIVE,REOPENED</Criteria>`)
	}
	if afterID > 0 {
		fmt.Fprintf(&crit, `<Criteria field="id" operator="GREATER">%d</Criteria>`, afterID)
	}

	// The open-findings search is what tickets are built from, so it asks
	// for the verbose record: each finding's request, payload and the proof
	// in the response (shape confirmed with cti-appreport --probe-findings).
	// Smaller pages: a verbose finding carries its evidence.
	prefs := fmt.Sprintf(`<limitResults>%d</limitResults>`, pageSize)
	if open {
		prefs = fmt.Sprintf(`<verbose>true</verbose><limitResults>%d</limitResults>`, verbosePageSize)
	}
	payload := fmt.Sprintf(
		`<ServiceRequest><preferences>%s</preferences>`+
			`<filters>%s</filters></ServiceRequest>`, prefs, crit.String())

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

	// Bounded: the verbose finding search carries evidence, and a response
	// past this is a fault, not a page.
	const limit = 64 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Qualys WAS response: %w", err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("the Qualys WAS response is over %d MB - not reading it", limit>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, a.authError(resp.StatusCode, body)
	}
	return body, nil
}

// get sends one GET to the /api/... family (the KnowledgeBase) and returns
// the body of a 2xx response. Same credentials and the same error advice as
// post.
func (a *API) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(a.username, a.password)
	req.Header.Set("X-Requested-With", "cti-agent")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qualys KnowledgeBase request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	const limit = 64 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the Qualys KnowledgeBase response: %w", err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("the Qualys KnowledgeBase response is over %d MB - not reading it", limit>>20)
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
			"qualys WAS rate-limited this request (HTTP %d) and the wait was longer "+
				"than QUALYS_RL_MAX_WAIT. The weekly report still has the counts from "+
				"the notification emails; only the per-finding detail is missing.\n"+
				"response: %s", status, trimmed)
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
	// Verbose only. Request headers are deliberately not read: they carry
	// the scan account's cookies, and nothing here needs them.
	Results []struct {
		Auth       bool     `xml:"authentication"`
		AccessPath []string `xml:"accessPath>list>Url"`
		Payloads   []struct {
			Payload  string `xml:"payload"`
			Method   string `xml:"request>method"`
			Link     string `xml:"request>link"`
			Response string `xml:"response"`
		} `xml:"payloads>list>PayloadInstance"`
	} `xml:"resultList>list>Result"`
}

// Evidence bounds, in runes. The proof is an excerpt: enough to recognise
// what the scanner saw, not the page.
const (
	maxProof      = 1500
	maxPayload    = 400
	maxLink       = 600
	maxAccessPath = 5
)

// evidence is the first detection's request and proof, redacted and bounded;
// nil when the record is not verbose or has none.
func (f wasFinding) evidence() *appscan.Evidence {
	for _, r := range f.Results {
		for _, p := range r.Payloads {
			e := &appscan.Evidence{
				Method:        clipRunes(strings.ToUpper(strings.TrimSpace(p.Method)), 16),
				Link:          clipRunes(appscan.RedactURL(strings.TrimSpace(p.Link)), maxLink),
				Authenticated: r.Auth,
			}
			if pl := strings.TrimSpace(p.Payload); pl != "" && !strings.EqualFold(pl, "N/A") {
				e.Payload = clipRunes(appscan.RedactURL(appscan.Redact(pl)), maxPayload)
			}
			e.Proof = clipRunes(appscan.RedactURL(appscan.Redact(strings.TrimSpace(maybeBase64(p.Response)))), maxProof)
			for i, u := range r.AccessPath {
				if i >= maxAccessPath {
					break
				}
				if u = strings.TrimSpace(u); u != "" {
					e.AccessPath = append(e.AccessPath, clipRunes(appscan.RedactURL(u), maxLink))
				}
			}
			if e.Link == "" && e.Proof == "" && e.Payload == "" {
				continue
			}
			return e
		}
	}
	return nil
}

// clipRunes cuts s to n runes, marking the cut.
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " [...]"
}

const unreadable = "[encoded response removed by cti-agent: not readable text, so it could not be checked for credentials]"

// maybeBase64 decodes s when it is entirely base64 and decodes to readable
// text - Qualys encodes some response bodies and not others. Anything else
// is returned as it came.
func maybeBase64(s string) string {
	t := strings.Join(strings.Fields(s), "")
	if len(t) < 16 || len(t)%4 != 0 || strings.Trim(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != "" {
		return s
	}
	dec, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return s // not base64 after all: ordinary text, redacted as such
	}
	// Base64 that does not decode to readable text cannot be checked for a
	// cookie, so it does not go out - fail closed, as Redact does.
	if !utf8.Valid(dec) {
		return unreadable
	}
	for _, r := range string(dec) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return unreadable
		}
	}
	return string(dec)
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
		Evidence:  f.evidence(),
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
