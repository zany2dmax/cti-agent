package qualys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// stub serves canned XML and records what was asked for.
func stub(t *testing.T, handler func(body string, call int) (int, string)) (*API, *[]string) {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		code, xmlBody := handler(string(b), len(bodies))
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, xmlBody)
	}))
	t.Cleanup(srv.Close)
	return NewAPI(srv.URL, "user", "pass"), &bodies
}

func page(hasMore bool, findings ...string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ServiceResponse>
  <responseCode>SUCCESS</responseCode>
  <count>%d</count>
  <hasMoreRecords>%t</hasMoreRecords>
  <data>%s</data>
</ServiceResponse>`, len(findings), hasMore, strings.Join(findings, ""))
}

func finding(id, qid int, name, url, status, sev string) string {
	return fmt.Sprintf(`<Finding>
    <id>%d</id><uniqueId>u-%d</uniqueId><qid>%d</qid>
    <name>%s</name><type>VULNERABILITY</type><severity>%s</severity>
    <url>%s</url><status>%s</status><param>q</param>
    <firstDetectedDate>2026-09-01T10:00:00Z</firstDetectedDate>
    <lastDetectedDate>2026-10-04T03:00:00Z</lastDetectedDate>
  </Finding>`, id, id, qid, name, sev, url, status)
}

func TestFindingsAreNormalisedFromTheWireFormat(t *testing.T) {
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, page(false,
			finding(1, 150085, "Cross-Site Scripting", "https://app.example/search", "ACTIVE", "5"))
	})

	got, err := api.Findings(context.Background(), appscan.ScanResult{App: "Example App"}, time.Time{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	f := got[0]
	if f.ID != "150085" {
		t.Errorf("ID = %q, want the QID", f.ID)
	}
	if f.Severity != 5 || f.Status != "ACTIVE" {
		t.Errorf("Severity = %d, Status = %q", f.Severity, f.Status)
	}
	if f.URL != "https://app.example/search" || f.Param != "q" {
		t.Errorf("URL = %q, Param = %q - these are what make a finding actionable", f.URL, f.Param)
	}
	if f.LastSeen.IsZero() {
		t.Error("LastSeen did not parse")
	}
}

func TestPaginationFollowsLastIdAndStops(t *testing.T) {
	api, bodies := stub(t, func(_ string, call int) (int, string) {
		switch call {
		case 1:
			return 200, page(true, finding(10, 1, "a", "u", "ACTIVE", "3"),
				finding(11, 2, "b", "u", "ACTIVE", "3"))
		default:
			return 200, page(false, finding(12, 3, "c", "u", "ACTIVE", "3"))
		}
	})

	got, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d findings across pages, want 3", len(got))
	}
	if len(*bodies) != 2 {
		t.Fatalf("made %d requests, want 2", len(*bodies))
	}
	// The second request must ask for ids above the highest already seen,
	// otherwise it re-reads page one forever.
	if !strings.Contains((*bodies)[1], `field="id" operator="GREATER">11<`) {
		t.Errorf("second request did not advance past id 11:\n%s", (*bodies)[1])
	}
}

func TestAServerClaimingMoreButSendingNoneDoesNotLoopForever(t *testing.T) {
	// hasMoreRecords true with an empty page leaves lastId unchanged, so the
	// next request is identical. Without a guard this spins until the context
	// dies - a lane that hangs rather than fails.
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, page(true)
	})
	if _, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{}); err == nil {
		t.Fatal("an empty page claiming more records was accepted")
	} else if !strings.Contains(err.Error(), "returned none") {
		t.Errorf("err = %v", err)
	}
}

func TestRunawayPaginationIsBoundedAndSaysSo(t *testing.T) {
	// Always one finding, always "more". A partial list returned here would
	// read as complete, which is worse than an error.
	id := 0
	api, _ := stub(t, func(string, int) (int, string) {
		id++
		return 200, page(true, finding(id, id, "x", "u", "ACTIVE", "1"))
	})
	_, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{})
	if err == nil {
		t.Fatal("pagination was unbounded")
	}
	if !strings.Contains(err.Error(), "partial list") {
		t.Errorf("the error does not explain why it refuses to return data: %v", err)
	}
}

func TestAWASLicenceFailureIsNotReportedAsABadPassword(t *testing.T) {
	// The failure people actually hit. A VM-only Qualys role returns 401 here
	// while the identical credentials keep working for the VM lane. Reported
	// as a bare "HTTP 401" that reads as a wrong password, and somebody goes
	// and rotates a working secret.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		api, _ := stub(t, func(string, int) (int, string) {
			return code, `<ServiceResponse><responseCode>UNAUTHORIZED</responseCode></ServiceResponse>`
		})
		_, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{})
		if err == nil {
			t.Fatalf("HTTP %d was not an error", code)
		}
		if !strings.Contains(err.Error(), "WAS module") {
			t.Errorf("HTTP %d: error does not mention the role: %v", code, err)
		}
		if !strings.Contains(err.Error(), "before rotating anything") {
			t.Errorf("HTTP %d: error does not warn against rotating a good secret", code)
		}
	}
}

func TestRateLimitingSaysWhatIsStillAvailable(t *testing.T) {
	// The counts come from the notification email and do not depend on this
	// API, so a 429 costs detail and not the report.
	api, _ := stub(t, func(string, int) (int, string) {
		return http.StatusTooManyRequests, "slow down"
	})
	// No waiting here: the limiter's retry is tested in internal/qualysrl.
	api.limiter.MaxWait = 0
	_, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{})
	if err == nil || !strings.Contains(err.Error(), "still has the counts") {
		t.Errorf("err = %v", err)
	}
}

func TestAnApiErrorResponseIsReportedWithItsMessage(t *testing.T) {
	// 200 with responseCode != SUCCESS. Reading the data block anyway would
	// produce zero findings and look like a clean application.
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, `<ServiceResponse><responseCode>INVALID_REQUEST</responseCode>
			<responseErrorDetails><errorMessage>bad field name</errorMessage></responseErrorDetails>
			<data/></ServiceResponse>`
	})
	_, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{})
	if err == nil {
		t.Fatal("an INVALID_REQUEST response was treated as zero findings")
	}
	if !strings.Contains(err.Error(), "bad field name") {
		t.Errorf("the vendor's message was dropped: %v", err)
	}
}

func TestTheApplicationNameIsEscapedIntoTheQuery(t *testing.T) {
	// The name comes from a scan notification, which arrives at a published
	// address anyone can write to. Unescaped, it would alter the query this
	// code is building - the same injection shape as any other unescaped
	// interpolation, in XML rather than SQL.
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })

	_, err := api.Findings(context.Background(), appscan.ScanResult{
		App: `App</Criteria><Criteria field="x" operator="EQUALS">y`}, time.Time{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	body := (*bodies)[0]
	// The injected criterion, specifically - not a count. The query now
	// carries a second, legitimate criterion (type = VULNERABILITY), and a
	// count-based check would have to be re-tuned every time one is added.
	if strings.Contains(body, `<Criteria field="x"`) {
		t.Errorf("injected Criteria survived escaping:\n%s", body)
	}
	if !strings.Contains(body, "&lt;/Criteria&gt;") {
		t.Errorf("the name was not escaped:\n%s", body)
	}
}

func TestTheApplicationIdIsPreferredOverTheName(t *testing.T) {
	// The name the email path supplies is derived from the scan title and on
	// a real estate almost never equals the scanner's application name, so a
	// name-keyed search quietly returned nothing. The id from the scan list is
	// exact.
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })
	_, err := api.Findings(context.Background(),
		appscan.ScanResult{App: "Example", AppID: "1000000001"}, time.Time{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	body := (*bodies)[0]
	if !strings.Contains(body, `<Criteria field="webApp.id" operator="EQUALS">1000000001</Criteria>`) {
		t.Errorf("the search did not key on webApp.id:\n%s", body)
	}
	if strings.Contains(body, `field="webApp.name"`) {
		t.Errorf("the search also filtered on a title-derived name:\n%s", body)
	}
}

func TestSinceIsOmittedWhenZero(t *testing.T) {
	// A zero time must mean "no lower bound", not "since year zero" - which
	// Qualys may reject or silently treat as something else.
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })
	if _, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains((*bodies)[0], "lastDetectedDate") {
		t.Errorf("a zero since produced a date filter:\n%s", (*bodies)[0])
	}

	api2, bodies2 := stub(t, func(string, int) (int, string) { return 200, page(false) })
	when := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	if _, err := api2.Findings(context.Background(), appscan.ScanResult{App: "App"}, when); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*bodies2)[0], "2026-09-27T00:00:00Z") {
		t.Errorf("since was not sent:\n%s", (*bodies2)[0])
	}
}

func TestAFindingWithNoQidFallsBackToItsUniqueId(t *testing.T) {
	// Information-gathered entries sometimes carry no QID. An empty ID would
	// make two unrelated findings look like the same one.
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, page(false, finding(7, 0, "Information", "u", "ACTIVE", "1"))
	})
	got, err := api.Findings(context.Background(), appscan.ScanResult{App: "App"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ID != "u-7" {
		t.Errorf("ID = %q, want the uniqueId", got[0].ID)
	}
}

// The compile-time assertion that matters: *API really does satisfy the
// interface the weekly report will hold it by. If the signature drifts, the
// build fails here rather than at the one call site.
//
// An earlier version of this "test" declared a local shim type and asserted
// that IT satisfied a locally declared interface - which is true by
// construction, passes forever, and proves nothing about API at all.
var _ appscan.DetailFetcher = (*API)(nil)

func TestOnlyVulnerabilitiesAreRequested(t *testing.T) {
	// Verified against the live API. Unfiltered, a real application's first
	// page was nothing but information-gathered items the report never shows.
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })
	if _, err := api.Findings(context.Background(),
		appscan.ScanResult{AppID: "1000000001"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*bodies)[0], `<Criteria field="type" operator="EQUALS">VULNERABILITY</Criteria>`) {
		t.Errorf("the search is not limited to vulnerabilities:\n%s", (*bodies)[0])
	}
}

func TestPotentialAndIgnoredAreRead(t *testing.T) {
	// Shape from a real response; values invented.
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, page(false, `<Finding>
      <id>1</id><uniqueId>u-1</uniqueId><qid>150520</qid>
      <name><![CDATA[Information Disclosure]]></name><type>VULNERABILITY</type>
      <potential>true</potential><findingType>QUALYS</findingType>
      <severity>2</severity><url><![CDATA[https://app.example/]]></url>
      <status>NEW</status>
      <firstDetectedDate>2026-10-01T00:00:00Z</firstDetectedDate>
      <lastDetectedDate>2026-10-04T00:00:00Z</lastDetectedDate>
      <timesDetected>1</timesDetected>
      <webApp><id>1</id><name><![CDATA[App]]></name></webApp>
      <isIgnored>true</isIgnored>
    </Finding>`)
	})
	got, err := api.Findings(context.Background(), appscan.ScanResult{AppID: "1"}, time.Time{})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if !got[0].Potential || !got[0].Ignored {
		t.Errorf("potential/isIgnored were not read: %+v", got[0])
	}
	if got[0].Param != "" {
		t.Errorf("Param = %q; the real response carries none at top level", got[0].Param)
	}
}

func TestOpenFindingsAskForEveryOpenFindingNotThisWeeks(t *testing.T) {
	// A ticket built from "detected this week" would be told a finding the
	// week's scan did not re-test was fixed.
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })
	if _, err := api.OpenFindings(context.Background(), appscan.ScanResult{App: "App", AppID: "42"}); err != nil {
		t.Fatal(err)
	}
	b := (*bodies)[0]
	if strings.Contains(b, "lastDetectedDate") {
		t.Errorf("open findings were limited to recent detections:\n%s", b)
	}
	if !strings.Contains(b, `<Criteria field="status" operator="IN">NEW,ACTIVE,REOPENED</Criteria>`) {
		t.Errorf("open findings not filtered on status:\n%s", b)
	}
	if !strings.Contains(b, `field="webApp.id" operator="EQUALS">42<`) {
		t.Errorf("not keyed on the application id:\n%s", b)
	}
}

// verboseFinding is the shape of a live verbose record, with invented values.
// headers is the base64 request-header block; response is the raw response.
func verboseFinding(response string) string {
	headers := base64.StdEncoding.EncodeToString([]byte("Referer: x\nCookie: s=1\n"))
	return `<Finding><id>1</id><qid>150222</qid><name><![CDATA[Reverse Tabnabbing]]></name>` +
		`<type>VULNERABILITY</type><potential>false</potential>` +
		`<resultList><count>1</count><list><Result><authentication>false</authentication>` +
		`<accessPath><count>2</count><list><Url><![CDATA[https://app.example.com/]]></Url>` +
		`<Url><![CDATA[https://app.example.com/a/]]></Url></list></accessPath><ajax>false</ajax>` +
		`<payloads><count>1</count><list><PayloadInstance><payload><![CDATA[N/A]]></payload>` +
		`<request><method><![CDATA[GET]]></method><link><![CDATA[https://app.example.com/a/b/]]></link>` +
		`<headers><![CDATA[` + headers + `]]></headers></request>` +
		`<response><![CDATA[` + response + `]]></response></PayloadInstance></list></payloads>` +
		`</Result></list></resultList><severity>3</severity>` +
		`<url><![CDATA[https://app.example.com/a/b/]]></url><status>ACTIVE</status></Finding>`
}

func openOne(t *testing.T, rec string) appscan.Finding {
	t.Helper()
	api, _ := stub(t, func(string, int) (int, string) { return 200, page(false, rec) })
	got, err := api.OpenFindings(context.Background(), appscan.ScanResult{App: "App", AppID: "1234"})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	return got[0]
}

func TestVerboseEvidenceIsParsedAndHeadersAreNeverCarried(t *testing.T) {
	f := openOne(t, verboseFinding(`Vulnerable blank target(s) found: <a href="https://x.example.org/" target="_blank">x</a>`))
	e := f.Evidence
	if e == nil {
		t.Fatal("no evidence parsed")
	}
	if e.Method != "GET" || e.Link != "https://app.example.com/a/b/" {
		t.Errorf("request = %s %s", e.Method, e.Link)
	}
	if len(e.AccessPath) != 2 {
		t.Errorf("access path = %v", e.AccessPath)
	}
	if e.Payload != "" {
		t.Errorf("payload N/A was kept: %q", e.Payload)
	}
	if !strings.Contains(e.Proof, "Vulnerable blank target") {
		t.Errorf("proof = %q", e.Proof)
	}
	js, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "s=1") || strings.Contains(string(js), "Cookie") {
		t.Errorf("request headers leaked into the finding: %s", js)
	}
}

func TestABase64ResponseIsDecoded(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("Server error: stack trace for /a/b/ shown"))
	f := openOne(t, verboseFinding(enc))
	if f.Evidence == nil || !strings.Contains(f.Evidence.Proof, "stack trace for /a/b/") {
		t.Errorf("response not decoded: %+v", f.Evidence)
	}
}

func TestASetCookieLineInTheResponseIsRedacted(t *testing.T) {
	f := openOne(t, verboseFinding("HTTP/1.1 200 OK\nSet-Cookie: abc=def\nContent-Type: text/html\n\nhello"))
	if f.Evidence == nil {
		t.Fatal("no evidence")
	}
	if strings.Contains(f.Evidence.Proof, "abc=def") {
		t.Errorf("cookie survived: %q", f.Evidence.Proof)
	}
	if !strings.Contains(f.Evidence.Proof, "hello") {
		t.Errorf("the rest of the proof was lost: %q", f.Evidence.Proof)
	}
}

func TestALongProofIsClipped(t *testing.T) {
	f := openOne(t, verboseFinding(strings.Repeat("é", 5000)))
	if f.Evidence == nil {
		t.Fatal("no evidence")
	}
	if n := len([]rune(f.Evidence.Proof)); n > 1500+len(" [...]") || n <= 1500 {
		t.Errorf("proof is %d runes; want 1500 plus the cut marker", n)
	}
	if !strings.HasSuffix(f.Evidence.Proof, "[...]") {
		t.Errorf("the cut is not marked: ...%q", f.Evidence.Proof[len(f.Evidence.Proof)-12:])
	}
}

func TestANonVerboseRecordHasNoEvidence(t *testing.T) {
	f := openOne(t, finding(1, 150085, "Cross-Site Scripting", "https://app.example.com/s", "ACTIVE", "5"))
	if f.Evidence != nil {
		t.Errorf("evidence invented: %+v", f.Evidence)
	}
}

func TestOnlyTheOpenSearchIsVerbose(t *testing.T) {
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })
	sr := appscan.ScanResult{App: "App", AppID: "1234"}
	if _, err := api.OpenFindings(context.Background(), sr); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Findings(context.Background(), sr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	open, weekly := (*bodies)[0], (*bodies)[1]
	if !strings.Contains(open, "<verbose>true</verbose>") || !strings.Contains(open, "<limitResults>100</limitResults>") {
		t.Errorf("open search is not verbose with 100 per page:\n%s", open)
	}
	if strings.Contains(weekly, "verbose") {
		t.Errorf("the weekly search asked for verbose:\n%s", weekly)
	}
}

func TestAResponseOverTheLimitIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < 65; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	api := NewAPI(srv.URL, "user", "pass")
	_, err := api.OpenFindings(context.Background(), appscan.ScanResult{App: "App", AppID: "1234"})
	if err == nil || !strings.Contains(err.Error(), "over 64 MB") {
		t.Errorf("err = %v; want the size refusal", err)
	}
}

// Base64 that does not decode to readable text is removed, not passed on
// still encoded where no redaction can see inside it.
func TestUnreadableBase64ResponseIsRemoved(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("Set-Cookie: s=1\n\x80\x81\xfe\xff binary"))
	if got := maybeBase64(raw); got != unreadable {
		t.Errorf("got %q, want the unreadable marker", got)
	}
	if got := maybeBase64("plain text, not base64 at all"); got != "plain text, not base64 at all" {
		t.Errorf("plain text changed: %q", got)
	}
}
