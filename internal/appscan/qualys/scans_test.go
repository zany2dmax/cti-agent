package qualys

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// SYNTHETIC. The shape - element names, nesting, CDATA, the trailing and
// doubled spaces, which elements are absent on a cancelled or running scan -
// is copied from a real search/was/wasscan response. Every name, URL, id and
// reference is invented: real scan titles enumerate the web estate and say
// which applications have a login, and this repository is public.

// wasScanXML is one <WasScan>. authRecord "" omits <webAppAuthRecord>, and
// authStatus "" omits <summary> entirely, as Qualys does for a scan that did
// not finish.
func wasScanXML(id int, name, ref, typ, mode, appID, appName, authRecord, status, authStatus string, links int) string {
	rec := ""
	if authRecord != "" {
		rec = fmt.Sprintf(`<webAppAuthRecord><id>5%d</id><name><![CDATA[%s]]></name></webAppAuthRecord>`,
			id, authRecord)
	}
	summary := ""
	if authStatus != "" {
		summary = fmt.Sprintf(`<summary><crawlDuration>100</crawlDuration>`+
			`<linksCrawled>%d</linksCrawled><resultsStatus>SUCCESSFUL</resultsStatus>`+
			`<authStatus>%s</authStatus><os>Linux</os></summary>`, links, authStatus)
	}
	return fmt.Sprintf(`<WasScan>
      <id>%d</id>
      <name><![CDATA[%s]]></name>
      <reference>%s</reference>
      <type>%s</type>
      <mode>%s</mode>
      <multi>false</multi>
      <target>
        <webApp><id>%s</id><name><![CDATA[%s]]></name><url><![CDATA[https://%s.example]]></url></webApp>
        %s
        <scannerAppliance><type>EXTERNAL</type></scannerAppliance>
      </target>
      <profile><id>1</id><name><![CDATA[Default Options]]></name></profile>
      <launchedDate>2026-09-2%dT10:00:00Z</launchedDate>
      <launchedBy><id>9</id><username>example</username></launchedBy>
      <status>%s</status>
      <consolidatedStatus>%s</consolidatedStatus>
      %s
    </WasScan>`, id, name, ref, typ, mode, appID, appName, appID, rec, id%10, status, status, summary)
}

func scanPage(hasMore bool, scans ...string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ServiceResponse>
  <responseCode>SUCCESS</responseCode>
  <count>%d</count>
  <hasMoreRecords>%t</hasMoreRecords>
  <data>%s</data>
</ServiceResponse>`, len(scans), hasMore, strings.Join(scans, ""))
}

// realisticWeek is one of each case the real list contained.
func realisticWeek() []string {
	return []string{
		// Public site, no login. Name with a trailing space; title with a
		// doubled one.
		wasScanXML(101, "Example Site  Weekly Run #16", "was/1.101", "VULNERABILITY", "SCHEDULED",
			"9001", "Example Site ", "", "FINISHED", "NONE", 414),
		// The one application that logs in, and does.
		wasScanXML(102, "ExPortal Bimonthly Run #46", "was/1.102", "VULNERABILITY", "SCHEDULED",
			"9002", "Example Portal", "portal auth record", "FINISHED", "SUCCESSFUL", 60),
		// On-demand discovery troubleshooting a login: tests nothing.
		wasScanXML(103, "Staging - Sep 27", "was/1.103", "DISCOVERY", "ONDEMAND",
			"9003", "Example Staging", "staging auth", "FINISHED", "FAILED", 2),
		// Cancelled by hand: no <summary>.
		wasScanXML(104, "Sep 27", "was/1.104", "DISCOVERY", "ONDEMAND",
			"9003", "Example Staging", "staging auth", "CANCELED", "", 0),
		// Still running: no <summary>.
		wasScanXML(105, "Example Site  Weekly Run #17", "was/1.105", "VULNERABILITY", "SCHEDULED",
			"9001", "Example Site ", "", "RUNNING", "", 0),
	}
}

func TestTheScanListIsReadFromTheRealShape(t *testing.T) {
	got, more, err := parseScans([]byte(scanPage(false, realisticWeek()...)))
	if err != nil {
		t.Fatalf("parseScans: %v", err)
	}
	if more || len(got) != 5 {
		t.Fatalf("got %d scans, more=%v", len(got), more)
	}
	s := got[0]
	if s.ID != 101 || s.Reference != "was/1.101" || s.WebAppID != "9001" {
		t.Errorf("identity: %+v", s)
	}
	// The raw name has a trailing space and the title a doubled one. Left as
	// they are, one application keyed by name becomes two.
	if s.WebAppName != "Example Site" {
		t.Errorf("WebAppName = %q, want whitespace tidied", s.WebAppName)
	}
	if s.Name != "Example Site Weekly Run #16" {
		t.Errorf("Name = %q, want whitespace tidied", s.Name)
	}
	if s.Type != "VULNERABILITY" || s.Mode != "SCHEDULED" || s.Status != "FINISHED" {
		t.Errorf("type/mode/status: %+v", s)
	}
	if s.AuthRecord != "" || s.AuthStatus != "NONE" || s.LinksCrawled != 414 {
		t.Errorf("auth/summary: %+v", s)
	}
	if !s.Launched.Equal(time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("Launched = %v", s.Launched)
	}
	if got[1].AuthRecord != "portal auth record" || got[1].AuthStatus != "SUCCESSFUL" {
		t.Errorf("an auth record was not read: %+v", got[1])
	}
}

func TestAScanWithNoSummaryIsNotReadAsAnEmptyResult(t *testing.T) {
	got, _, err := parseScans([]byte(scanPage(false, realisticWeek()...)))
	if err != nil {
		t.Fatal(err)
	}
	cancelled, running := got[3], got[4]
	if cancelled.Complete() || cancelled.InFlight() {
		t.Errorf("a cancelled scan is neither complete nor in flight: %+v", cancelled)
	}
	if !running.InFlight() || running.Complete() {
		t.Errorf("a running scan must read as in flight: %+v", running)
	}
	if !got[0].Complete() {
		t.Error("a finished, successful scan did not read as complete")
	}
}

func TestAnUnknownStatusIsTerminalNotInFlight(t *testing.T) {
	// Listing the "not yet" statuses rather than the "done" ones means a
	// status nobody has seen surfaces somewhere instead of being skipped for
	// ever as a scan that is always about to finish.
	if (Scan{Status: "SCANNER_NOT_AVAILABLE"}).InFlight() {
		t.Error("an unrecognised status was treated as in flight")
	}
}

func TestTheScanQueryUsesOnlyElementsTheSchemaAccepts(t *testing.T) {
	// The first probe of this endpoint added <verbose>, which does not exist,
	// and the whole request came back INVALID_XML.
	q := scanQuery(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC), 0)
	if strings.Contains(q, "verbose") {
		t.Errorf("the query carries an element the schema rejects:\n%s", q)
	}
	if !strings.Contains(q, `<Criteria field="launchedDate" operator="GREATER">2026-09-21T00:00:00Z</Criteria>`) {
		t.Errorf("the window is missing:\n%s", q)
	}
	if !strings.Contains(scanQuery(time.Time{}, 77), `<Criteria field="id" operator="GREATER">77</Criteria>`) {
		t.Error("paging does not advance by id")
	}
}

func TestTheScanListPagesAndStops(t *testing.T) {
	api, bodies := stub(t, func(_ string, call int) (int, string) {
		if call == 1 {
			return 200, scanPage(true, realisticWeek()[0], realisticWeek()[1])
		}
		return 200, scanPage(false, realisticWeek()[2])
	})
	got, err := api.Scans(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Scans: %v", err)
	}
	if len(got) != 3 || len(*bodies) != 2 {
		t.Fatalf("got %d scans in %d calls", len(got), len(*bodies))
	}
	if !strings.Contains((*bodies)[1], `<Criteria field="id" operator="GREATER">102</Criteria>`) {
		t.Errorf("page two did not start after the last id:\n%s", (*bodies)[1])
	}
}

func TestAScanListClaimingMoreButSendingNoneDoesNotLoop(t *testing.T) {
	api, _ := stub(t, func(string, int) (int, string) { return 200, scanPage(true) })
	if _, err := api.Scans(context.Background(), time.Time{}); err == nil {
		t.Fatal("a server saying 'more' with no records was accepted")
	}
}

func TestAScanListErrorIsReportedWithItsMessage(t *testing.T) {
	// The exact error the first probe produced.
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, `<ServiceResponse><responseCode>INVALID_XML</responseCode>` +
			`<responseErrorDetails><errorMessage>Invalid content was found starting ` +
			`with element 'verbose'.</errorMessage></responseErrorDetails></ServiceResponse>`
	})
	_, err := api.Scans(context.Background(), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "INVALID_XML") ||
		!strings.Contains(err.Error(), "verbose") {
		t.Errorf("err = %v", err)
	}
}

func TestTheScanListExplainsAMissingWasRole(t *testing.T) {
	api, _ := stub(t, func(string, int) (int, string) { return 403, "<html>forbidden</html>" })
	_, err := api.Scans(context.Background(), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "WAS module") {
		t.Errorf("a 403 was not explained as a role problem: %v", err)
	}
}
