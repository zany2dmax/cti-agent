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
	"github.com/zany2dmax/cti-agent/internal/qualysrl"
)

// THE WAS REPORT API
//
// Four calls per report, all on the QPS family the finding search uses:
//
//	POST /qps/rest/3.0/create/was/report        -> report id
//	GET  /qps/rest/3.0/status/was/report/<id>   -> RUNNING | COMPLETE | ERROR
//	GET  /qps/rest/3.0/download/was/report/<id> -> the file (HTML_ZIPPED: a zip)
//	POST /qps/rest/3.0/delete/was/report/<id>
//
// The report is deleted from Qualys once downloaded, success or failure:
// reports accumulate in the subscription's Report list otherwise, one per
// application per week, and each holds the scanner's session cookies.
//
// NOT YET VERIFIED AGAINST THE LIVE API. The element names below follow the
// WAS API guide. cti-appreport --dump-request prints the exact body sent, and
// --request-file sends a corrected one without a rebuild, so a field-name
// mismatch is a fleet.env-free fix on the box while probing.

// Name implements appscan.ReportFetcher: the same key as the notification parser.
func (a *API) Name() string { return Provider{}.Name() }

// RateStatus implements appscan.RateReporter.
func (a *API) RateStatus() string { return a.limiter.Snapshot().String() }

// ReportTemplate, when set, replaces the built-in create-report body.
// "{{APP_ID}}" and "{{NAME}}" are substituted, XML-escaped. For probing only.
func (a *API) SetReportTemplate(t string) { a.reportTemplate = t }

// Report polling: quick at first, then backing off, so a fast report costs
// two or three status calls and a slow one does not spend the budget.
var pollSchedule = []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second,
	20 * time.Second, 30 * time.Second}

var maxPollInterval = 60 * time.Second

// ReportTimeout bounds one report from create to download, when the request
// does not say.
const ReportTimeout = 10 * time.Minute

// AppReport implements appscan.ReportFetcher.
func (a *API) AppReport(ctx context.Context, req appscan.ReportRequest) (appscan.Report, error) {
	if strings.TrimSpace(req.AppID) == "" {
		return appscan.Report{}, fmt.Errorf("qualys WAS report: no web application id for %q", req.App)
	}
	if _, err := strconv.ParseInt(req.AppID, 10, 64); err != nil {
		return appscan.Report{}, fmt.Errorf("qualys WAS report: web application id %q is not a number", req.AppID)
	}
	now := time.Now().UTC()
	name := fmt.Sprintf("cti-agent %s %s", oneLine(req.App, 80), now.Format("2006-01-02"))
	body := a.ReportRequestBody(req, name)

	resp, err := a.post(ctx, "/qps/rest/3.0/create/was/report", body)
	if err != nil {
		return appscan.Report{}, fmt.Errorf("creating the report: %w", err)
	}
	id, err := parseReportID(resp)
	if err != nil {
		return appscan.Report{}, fmt.Errorf("creating the report: %w", err)
	}
	out := appscan.Report{Provider: a.Name(), AppID: req.AppID, App: req.App,
		Generated: now, RemoteID: strconv.FormatInt(id, 10), Kept: req.Keep}

	// Deleted on every path out, with its own context: the run's may be the
	// reason we are leaving.
	if !req.Keep {
		defer func() {
			dctx, cancel := context.WithTimeout(qualysrl.Cleanup(context.Background()),
				a.limiter.MaxWait+60*time.Second)
			defer cancel()
			if _, err := a.post(dctx, "/qps/rest/3.0/delete/was/report/"+out.RemoteID, ""); err != nil {
				a.warnf("report %s for %q was not deleted from Qualys - remove it from the "+
					"WAS Reports list by hand: %s", out.RemoteID, req.App, oneLine(err.Error(), 300))
			}
		}()
	}

	limit := req.Timeout
	if limit <= 0 {
		limit = ReportTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if err := a.waitReport(rctx, id); err != nil {
		return out, err
	}
	data, err := a.download(rctx, "/qps/rest/3.0/download/was/report/"+out.RemoteID)
	if err != nil {
		return out, fmt.Errorf("downloading report %s: %w", out.RemoteID, err)
	}
	if !appscan.IsZip(data) {
		// HTML_ZIPPED should already be a zip; if Qualys hands back the HTML
		// itself, zip it rather than attach something else.
		if data, err = appscan.ZipOne("report.html", data, now); err != nil {
			return out, err
		}
	}
	out.Body = data
	return out, nil
}

// ReportRequestBody is the create-report XML for one application.
func (a *API) ReportRequestBody(req appscan.ReportRequest, name string) string {
	if a.reportTemplate != "" {
		r := strings.NewReplacer("{{APP_ID}}", xmlEscape(req.AppID), "{{NAME}}", xmlEscape(name))
		return r.Replace(a.reportTemplate)
	}
	statuses := req.Statuses
	if len(statuses) == 0 {
		statuses = appscan.OpenStatuses
	}
	var st strings.Builder
	for _, s := range statuses {
		fmt.Fprintf(&st, "<WebAppFindingStatus>%s</WebAppFindingStatus>", xmlEscape(strings.ToUpper(s)))
	}
	return `<ServiceRequest><data><Report>` +
		`<name>` + xmlEscape(name) + `</name>` +
		`<description>Open vulnerabilities, for the application's ticket. Filed by cti-agent.</description>` +
		`<format>HTML_ZIPPED</format>` +
		`<type>WAS_WEBAPP_REPORT</type>` +
		`<config><webAppReport>` +
		`<target><webapps><WebApp><id>` + xmlEscape(req.AppID) + `</id></WebApp></webapps></target>` +
		`<display>` +
		`<contents>` +
		`<WebAppReportContent>DESCRIPTION</WebAppReportContent>` +
		`<WebAppReportContent>SUMMARY</WebAppReportContent>` +
		`<WebAppReportContent>RESULTS</WebAppReportContent>` +
		`<WebAppReportContent>INDIVIDUAL_RECORDS</WebAppReportContent>` +
		`<WebAppReportContent>RECORD_DETAILS</WebAppReportContent>` +
		`<WebAppReportContent>APPENDIX</WebAppReportContent>` +
		`</contents>` +
		`<groups><WebAppReportGroup>QID</WebAppReportGroup></groups>` +
		`</display>` +
		`<filters><status>` + st.String() + `</status></filters>` +
		`</webAppReport></config>` +
		`</Report></data></ServiceRequest>`
}

func (a *API) waitReport(ctx context.Context, id int64) error {
	path := "/qps/rest/3.0/status/was/report/" + strconv.FormatInt(id, 10)
	for i := 0; ; i++ {
		d := maxPollInterval
		if i < len(pollSchedule) {
			d = pollSchedule[i]
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("report %d was not ready in time: %w", id, ctx.Err())
		case <-t.C:
		}
		body, err := a.get(ctx, path)
		if err != nil {
			return fmt.Errorf("checking report %d: %w", id, err)
		}
		status, err := parseReportStatus(body)
		if err != nil {
			return fmt.Errorf("checking report %d: %w", id, err)
		}
		switch status {
		case "COMPLETE":
			return nil
		case "ERROR", "FAILED", "CANCELED", "CANCELLED":
			return fmt.Errorf("qualys could not generate report %d (status %s)", id, status)
		}
	}
}

// download GETs a report file. Not get(): that one is for the KnowledgeBase's
// XML, and a report is bounded by the report limit instead.
func (a *API) download(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(a.username, a.password)
	req.Header.Set("X-Requested-With", "cti-agent")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qualys WAS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, appscan.MaxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the report: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, a.authError(resp.StatusCode, body)
	}
	if len(body) > appscan.MaxReportBytes {
		return nil, fmt.Errorf("the report is over %d MB - not downloading it", appscan.MaxReportBytes>>20)
	}
	// A QPS error comes back as a 200 with a ServiceResponse, not a file.
	if strings.HasPrefix(strings.TrimSpace(string(body[:min(len(body), 200)])), "<?xml") ||
		strings.Contains(string(body[:min(len(body), 200)]), "<ServiceResponse") {
		var r reportResponse
		if xml.Unmarshal(body, &r) == nil && r.ResponseCode != "" && r.ResponseCode != "SUCCESS" {
			return nil, fmt.Errorf("qualys WAS: %s: %s", r.ResponseCode,
				strings.TrimSpace(r.ResponseErrorDetails.ErrorMessage))
		}
	}
	return body, nil
}

type reportResponse struct {
	XMLName              xml.Name `xml:"ServiceResponse"`
	ResponseCode         string   `xml:"responseCode"`
	ResponseErrorDetails struct {
		ErrorMessage string `xml:"errorMessage"`
	} `xml:"responseErrorDetails"`
	Data struct {
		Reports []struct {
			ID     int64  `xml:"id"`
			Status string `xml:"status"`
		} `xml:"Report"`
	} `xml:"data"`
}

func parseReport(body []byte) (reportResponse, error) {
	var r reportResponse
	if err := xml.Unmarshal(body, &r); err != nil {
		return r, fmt.Errorf("qualys WAS: response is not the expected XML: %w", err)
	}
	if r.ResponseCode != "SUCCESS" {
		return r, fmt.Errorf("qualys WAS: %s: %s", r.ResponseCode,
			strings.TrimSpace(r.ResponseErrorDetails.ErrorMessage))
	}
	if len(r.Data.Reports) != 1 {
		return r, fmt.Errorf("qualys WAS: expected one report in the response, got %d", len(r.Data.Reports))
	}
	return r, nil
}

func parseReportID(body []byte) (int64, error) {
	r, err := parseReport(body)
	if err != nil {
		return 0, err
	}
	if r.Data.Reports[0].ID <= 0 {
		return 0, fmt.Errorf("qualys WAS: the created report has no id")
	}
	return r.Data.Reports[0].ID, nil
}

func parseReportStatus(body []byte) (string, error) {
	r, err := parseReport(body)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(strings.TrimSpace(r.Data.Reports[0].Status)), nil
}

func oneLine(s string, max int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > max {
		r = r[:max]
	}
	return string(r)
}

// Check makes one cheap authenticated call - a count of the web
// applications - so cti-appreport --check can show that the credentials
// reach WAS and what the rate-limit headers say.
func (a *API) Check(ctx context.Context) (int, error) {
	body, err := a.post(ctx, "/qps/rest/3.0/count/was/webapp", "<ServiceRequest></ServiceRequest>")
	if err != nil {
		return 0, err
	}
	var r serviceResponse
	if err := xml.Unmarshal(body, &r); err != nil {
		return 0, fmt.Errorf("qualys WAS: response is not the expected XML: %w", err)
	}
	if r.ResponseCode != "SUCCESS" {
		return 0, fmt.Errorf("qualys WAS: %s: %s", r.ResponseCode,
			strings.TrimSpace(r.ResponseErrorDetails.ErrorMessage))
	}
	return r.Count, nil
}

// ProbeFindings returns the raw verbose finding search for one application,
// limited to n open vulnerabilities - for seeing the field names the ticket
// text will be built from. The caller redacts before printing.
func (a *API) ProbeFindings(ctx context.Context, appID string, n int) ([]byte, error) {
	if _, err := strconv.ParseInt(appID, 10, 64); err != nil {
		return nil, fmt.Errorf("web application id %q is not a number", appID)
	}
	payload := fmt.Sprintf(`<ServiceRequest><preferences><verbose>true</verbose>`+
		`<limitResults>%d</limitResults></preferences><filters>`+
		`<Criteria field="webApp.id" operator="EQUALS">%s</Criteria>`+
		`<Criteria field="type" operator="EQUALS">VULNERABILITY</Criteria>`+
		`<Criteria field="status" operator="IN">NEW,ACTIVE,REOPENED</Criteria>`+
		`</filters></ServiceRequest>`, n, xmlEscape(appID))
	return a.post(ctx, "/qps/rest/3.0/search/was/finding/", payload)
}
