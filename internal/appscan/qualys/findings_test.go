package qualys

import (
	"context"
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

	got, err := api.Findings(context.Background(), "Example App", time.Time{})
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

	got, err := api.Findings(context.Background(), "App", time.Time{})
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
	if _, err := api.Findings(context.Background(), "App", time.Time{}); err == nil {
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
	_, err := api.Findings(context.Background(), "App", time.Time{})
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
		_, err := api.Findings(context.Background(), "App", time.Time{})
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
	_, err := api.Findings(context.Background(), "App", time.Time{})
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
	_, err := api.Findings(context.Background(), "App", time.Time{})
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

	_, err := api.Findings(context.Background(),
		`App</Criteria><Criteria field="x" operator="EQUALS">y`, time.Time{})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	body := (*bodies)[0]
	if strings.Count(body, "<Criteria") != 1 {
		t.Errorf("injected Criteria survived escaping:\n%s", body)
	}
	if !strings.Contains(body, "&lt;/Criteria&gt;") {
		t.Errorf("the name was not escaped:\n%s", body)
	}
}

func TestSinceIsOmittedWhenZero(t *testing.T) {
	// A zero time must mean "no lower bound", not "since year zero" - which
	// Qualys may reject or silently treat as something else.
	api, bodies := stub(t, func(string, int) (int, string) { return 200, page(false) })
	if _, err := api.Findings(context.Background(), "App", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains((*bodies)[0], "lastDetectedDate") {
		t.Errorf("a zero since produced a date filter:\n%s", (*bodies)[0])
	}

	api2, bodies2 := stub(t, func(string, int) (int, string) { return 200, page(false) })
	when := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	if _, err := api2.Findings(context.Background(), "App", when); err != nil {
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
	got, err := api.Findings(context.Background(), "App", time.Time{})
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
