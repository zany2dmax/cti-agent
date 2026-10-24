package qualys

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

const zipBytes = "PK\x03\x04 rest of a zip"

type reportServer struct {
	mu       sync.Mutex
	calls    []string
	created  string
	statuses []string // returned in turn by the status call
	download string
}

func (s *reportServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("X-RateLimit-Limit", "300")
	w.Header().Set("X-RateLimit-Remaining", "200")
	switch {
	case strings.HasPrefix(r.URL.Path, "/qps/rest/3.0/create/was/report"):
		b, _ := io.ReadAll(r.Body)
		s.created = string(b)
		_, _ = io.WriteString(w, `<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count>`+
			`<data><Report><id>4242</id></Report></data></ServiceResponse>`)
	case strings.HasPrefix(r.URL.Path, "/qps/rest/3.0/status/was/report/4242"):
		st := s.statuses[0]
		if len(s.statuses) > 1 {
			s.statuses = s.statuses[1:]
		}
		_, _ = io.WriteString(w, `<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count>`+
			`<data><Report><status>`+st+`</status></Report></data></ServiceResponse>`)
	case strings.HasPrefix(r.URL.Path, "/qps/rest/3.0/download/was/report/4242"):
		_, _ = io.WriteString(w, s.download)
	case strings.HasPrefix(r.URL.Path, "/qps/rest/3.0/delete/was/report/4242"):
		_, _ = io.WriteString(w, `<ServiceResponse><responseCode>SUCCESS</responseCode></ServiceResponse>`)
	default:
		http.NotFound(w, r)
	}
}

func fastPolls(t *testing.T) {
	old, oldMax := pollSchedule, maxPollInterval
	pollSchedule, maxPollInterval = []time.Duration{time.Millisecond}, time.Millisecond
	t.Cleanup(func() { pollSchedule, maxPollInterval = old, oldMax })
}

func TestAppReportCreatePollDownloadDelete(t *testing.T) {
	fastPolls(t)
	s := &reportServer{statuses: []string{"RUNNING", "COMPLETE"}, download: zipBytes}
	srv := httptest.NewServer(s)
	defer srv.Close()
	api := NewAPI(srv.URL, "u", "p")

	r, err := api.AppReport(context.Background(), appscan.ReportRequest{AppID: "123", App: "Shop <test>"})
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != zipBytes || r.RemoteID != "4242" || r.Provider != "qualys-was" {
		t.Fatalf("report = %+v", r)
	}
	want := []string{"POST /qps/rest/3.0/create/was/report", "GET /qps/rest/3.0/status/was/report/4242",
		"GET /qps/rest/3.0/status/was/report/4242", "GET /qps/rest/3.0/download/was/report/4242",
		"POST /qps/rest/3.0/delete/was/report/4242"}
	if strings.Join(s.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(s.calls, "\n"))
	}
	for _, w := range []string{"<id>123</id>", "HTML_ZIPPED", "WAS_WEBAPP_REPORT",
		"<WebAppFindingStatus>NEW</WebAppFindingStatus><WebAppFindingStatus>ACTIVE</WebAppFindingStatus>" +
			"<WebAppFindingStatus>REOPENED</WebAppFindingStatus>", "Shop &lt;test&gt;"} {
		if !strings.Contains(s.created, w) {
			t.Errorf("create body lacks %q:\n%s", w, s.created)
		}
	}
	if !strings.Contains(api.RateStatus(), "200 of 300") {
		t.Errorf("rate status = %q", api.RateStatus())
	}
}

// A failed report is still deleted.
func TestAppReportErrorStillDeletes(t *testing.T) {
	fastPolls(t)
	s := &reportServer{statuses: []string{"ERROR"}}
	srv := httptest.NewServer(s)
	defer srv.Close()
	_, err := NewAPI(srv.URL, "u", "p").AppReport(context.Background(), appscan.ReportRequest{AppID: "123"})
	if err == nil || !strings.Contains(err.Error(), "could not generate") {
		t.Fatalf("err = %v", err)
	}
	if last := s.calls[len(s.calls)-1]; last != "POST /qps/rest/3.0/delete/was/report/4242" {
		t.Fatalf("last call %q, want the delete", last)
	}
}

func TestAppReportKeepDoesNotDelete(t *testing.T) {
	fastPolls(t)
	s := &reportServer{statuses: []string{"COMPLETE"}, download: zipBytes}
	srv := httptest.NewServer(s)
	defer srv.Close()
	r, err := NewAPI(srv.URL, "u", "p").AppReport(context.Background(), appscan.ReportRequest{AppID: "123", Keep: true})
	if err != nil || !r.Kept {
		t.Fatalf("r %+v err %v", r, err)
	}
	for _, c := range s.calls {
		if strings.Contains(c, "delete") {
			t.Fatal("deleted a kept report")
		}
	}
}

// Bare HTML is zipped rather than attached as something else.
func TestAppReportZipsBareHTML(t *testing.T) {
	fastPolls(t)
	s := &reportServer{statuses: []string{"COMPLETE"}, download: "<html>report</html>"}
	srv := httptest.NewServer(s)
	defer srv.Close()
	r, err := NewAPI(srv.URL, "u", "p").AppReport(context.Background(), appscan.ReportRequest{AppID: "123"})
	if err != nil || !appscan.IsZip(r.Body) {
		t.Fatalf("err %v zip %v", err, appscan.IsZip(r.Body))
	}
}

// A QPS error returned as a 200 from the download is an error, not a file.
func TestAppReportDownloadErrorBody(t *testing.T) {
	fastPolls(t)
	s := &reportServer{statuses: []string{"COMPLETE"},
		download: `<?xml version="1.0"?><ServiceResponse><responseCode>NOT_FOUND</responseCode>` +
			`<responseErrorDetails><errorMessage>gone</errorMessage></responseErrorDetails></ServiceResponse>`}
	srv := httptest.NewServer(s)
	defer srv.Close()
	_, err := NewAPI(srv.URL, "u", "p").AppReport(context.Background(), appscan.ReportRequest{AppID: "123"})
	if err == nil || !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Fatalf("err = %v", err)
	}
}

func TestAppReportRejectsBadID(t *testing.T) {
	api := NewAPI("https://qualysapi.example.com", "u", "p")
	for _, id := range []string{"", "12</id><x>", "abc"} {
		if _, err := api.AppReport(context.Background(), appscan.ReportRequest{AppID: id}); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
}

func TestReportTemplateOverride(t *testing.T) {
	api := NewAPI("https://qualysapi.example.com", "u", "p")
	api.SetReportTemplate("<x><id>{{APP_ID}}</id><n>{{NAME}}</n></x>")
	got := api.ReportRequestBody(appscan.ReportRequest{AppID: "7"}, "a&b")
	if got != "<x><id>7</id><n>a&amp;b</n></x>" {
		t.Fatalf("got %q", got)
	}
}
