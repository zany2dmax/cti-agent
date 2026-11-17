package vmscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Invented titles and references, shaped like the real scan list.
const scanListXML = `<?xml version="1.0" encoding="UTF-8" ?>
<SCAN_LIST_OUTPUT><RESPONSE><DATETIME>2026-11-16T13:00:00Z</DATETIME><SCAN_LIST>
<SCAN><REF>scan/1794488418.15141</REF><TYPE>Scheduled</TYPE><TITLE><![CDATA[Weekly Scheduled Scan for Main]]></TITLE>
<USER_LOGIN>scanner</USER_LOGIN><LAUNCH_DATETIME>2026-11-12T13:00:18Z</LAUNCH_DATETIME><DURATION>08:27:28</DURATION>
<STATUS><STATE>Finished</STATE></STATUS>
<ASSET_GROUP_TITLE_LIST><ASSET_GROUP_TITLE><![CDATA[Alpha]]></ASSET_GROUP_TITLE><ASSET_GROUP_TITLE><![CDATA[` + "\ufeff" + `Beta  Site]]></ASSET_GROUP_TITLE></ASSET_GROUP_TITLE_LIST></SCAN>
<SCAN><REF>scan/1794488999.20000</REF><TYPE>Scheduled</TYPE><TITLE><![CDATA[Regional Weekly]]></TITLE>
<USER_LOGIN>scanner</USER_LOGIN><LAUNCH_DATETIME>2026-11-12T13:00:22Z</LAUNCH_DATETIME><DURATION>1 day 00:02:33</DURATION>
<STATUS><STATE>Finished</STATE></STATUS>
<ASSET_GROUP_TITLE_LIST><ASSET_GROUP_TITLE><![CDATA[Gamma]]></ASSET_GROUP_TITLE></ASSET_GROUP_TITLE_LIST></SCAN>
<SCAN><REF>scan/1794500000.1</REF><TYPE>On-Demand</TYPE><TITLE><![CDATA[Someone's test]]></TITLE>
<USER_LOGIN>person</USER_LOGIN><LAUNCH_DATETIME>2026-11-13T09:00:00Z</LAUNCH_DATETIME><DURATION>00:10:00</DURATION>
<STATUS><STATE>Finished</STATE></STATUS></SCAN>
</SCAN_LIST></RESPONSE></SCAN_LIST_OUTPUT>`

func TestParseScanList(t *testing.T) {
	scans, err := ParseScanList([]byte(scanListXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 {
		t.Fatalf("got %d scans", len(scans))
	}
	a := scans[0]
	if a.Title != "Weekly Scheduled Scan for Main" || a.Ref != "scan/1794488418.15141" || !a.Scheduled() ||
		!a.Finished() || !a.FromList || a.Duration != 8*time.Hour+27*time.Minute+28*time.Second {
		t.Errorf("first scan: %+v", a)
	}
	if !a.Start.Equal(time.Date(2026, 11, 12, 13, 0, 18, 0, time.UTC)) {
		t.Errorf("start %v", a.Start)
	}
	// The byte-order mark and the doubled space are gone from the group name.
	if strings.Join(a.TargetGroups, "|") != "Alpha|Beta Site" {
		t.Errorf("groups %q", a.TargetGroups)
	}
	if scans[1].Duration != 24*time.Hour+2*time.Minute+33*time.Second {
		t.Errorf("a day-long duration: %v", scans[1].Duration)
	}
	if scans[2].Scheduled() || len(scans[2].TargetGroups) != 0 {
		t.Errorf("the on-demand scan: %+v", scans[2])
	}
}

func TestATruncatedOrRefusedScanListIsAnError(t *testing.T) {
	truncated := strings.Replace(scanListXML, "</SCAN_LIST>",
		"</SCAN_LIST><WARNING><CODE>1980</CODE><TEXT>1000 record limit exceeded</TEXT></WARNING>", 1)
	if _, err := ParseScanList([]byte(truncated)); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("a truncated list must be refused: %v", err)
	}
	refused := `<SIMPLE_RETURN><RESPONSE><CODE>2000</CODE><TEXT>Bad Login/Password</TEXT></RESPONSE></SIMPLE_RETURN>`
	if _, err := ParseScanList([]byte(refused)); err == nil {
		t.Error("a login refusal must be an error, not an empty week")
	}
}

func TestFetchScansAsksForTheWindowAndTheAssetGroups(t *testing.T) {
	since := time.Date(2026, 11, 9, 13, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/2.0/fo/scan/" || q.Get("action") != "list" || q.Get("show_ags") != "1" ||
			q.Get("launched_after_datetime") != "2026-11-09T13:00:00Z" {
			t.Errorf("unexpected request %s", r.URL)
		}
		if r.Header.Get("X-Requested-With") == "" {
			t.Error("the Qualys API needs X-Requested-With")
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "p" {
			t.Error("no basic auth")
		}
		_, _ = w.Write([]byte(scanListXML))
	}))
	defer srv.Close()
	scans, err := FetchScans(context.Background(), srv.URL, "u", "p", since)
	if err != nil || len(scans) != 3 {
		t.Fatalf("scans %d, err %v", len(scans), err)
	}
}

func TestFetchScansReportsAnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	if _, err := FetchScans(context.Background(), srv.URL, "u", "p", time.Now()); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v", err)
	}
}

// The week of 2026-11-12: the list has both scans, the mail only one.
func TestTheListFindsTheScanWhoseNoticeWasLost(t *testing.T) {
	list, err := ParseScanList([]byte(scanListXML))
	if err != nil {
		t.Fatal(err)
	}
	notice := Scan{Title: "Weekly Scheduled Scan for Main", Ref: "scan/1794488418.15141", LaunchType: "Scheduled",
		Status: "Finished", HostsScanned: 9730, ActiveHosts: 1677, MessageID: "m1",
		TargetGroups: []string{"\ufeffAlpha", "Beta Site"}}
	old := Scan{Title: "Regional Weekly", Ref: "scan/1793883623.34769", LaunchType: "Scheduled",
		Status: "Finished", Start: time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC), MessageID: "m0"}

	w := Combine(WithNotices(list, []Scan{notice, old}), []string{"Weekly Scheduled Scan for Main", "Regional Weekly"})
	if len(w.Missing) != 0 || len(w.Scans) != 2 || len(w.Other) != 1 {
		t.Fatalf("missing %v scans %d other %d", w.Missing, len(w.Scans), len(w.Other))
	}
	main, regional := w.Scans[0], w.Scans[1]
	if main.NoNotice || main.HostsScanned != 9730 || main.MessageID != "m1" ||
		strings.Join(main.TargetGroups, "|") != "Alpha|Beta Site" {
		t.Errorf("the scan with a notice keeps its detail and the list's groups: %+v", main)
	}
	// The newest run of the regional scan is the listed one, not last week's notice.
	if !regional.NoNotice || !regional.Start.Equal(time.Date(2026, 11, 12, 13, 0, 22, 0, time.UTC)) ||
		strings.Join(regional.TargetGroups, "|") != "Gamma" {
		t.Errorf("the scan whose notice was lost: %+v", regional)
	}
	sub := w.Subject("Acme", time.Now())
	if strings.HasPrefix(sub, "[NO RESULT]") {
		t.Errorf("a scan Qualys lists is not missing: %q", sub)
	}
	txt := w.Text("Acme", time.Now())
	if !strings.Contains(txt, "never arrived") || strings.Contains(txt, "Addresses scanned 0") {
		t.Errorf("the report must say the notice was lost and not claim zero hosts:\n%s", txt)
	}
	if !strings.Contains(w.HTML("Acme", time.Now()), "did not arrive") {
		t.Error("the HTML must say the notice did not arrive")
	}
}
