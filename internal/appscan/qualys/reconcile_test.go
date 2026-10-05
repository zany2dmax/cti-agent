package qualys

import (
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

// All synthetic; see scans_test.go.

var window = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

func listScan(id int, ref, typ, mode, appID, app, rec, status, auth string, launched time.Time) Scan {
	return Scan{ID: id, Reference: ref, Type: typ, Mode: mode, WebAppID: appID,
		WebAppName: app, AuthRecord: rec, Status: status, AuthStatus: auth,
		Launched: launched, ResultsStatus: "SUCCESSFUL", LinksCrawled: 10}
}

// fromMail is what the notification parser produces: a title-derived name,
// a reference, counts, no application id.
func fromMail(ref, titleApp string) appscan.ScanResult {
	return appscan.ScanResult{
		Provider: "qualys-was", App: titleApp, Reference: ref, Complete: true,
		Status: "Finished : OK",
		Auth:   appscan.Auth{Status: "No Authentication specified"},
		AppState: appscan.Lifecycle{
			Active: appscan.Counts{Serious: 2, Minimal: 5},
		},
	}
}

func day(n int) time.Time { return window.Add(time.Duration(n) * 24 * time.Hour) }

func TestTheJoinIsOnTheReferenceAndTakesTheRealName(t *testing.T) {
	// The title-derived name ("ExHome") is not the application's name
	// ("Example Homepage") - on the real estate this was true of nearly every
	// scan, which is why the name-keyed detail lookup returned nothing.
	got, rec := Reconcile(
		[]appscan.ScanResult{fromMail("was/1.1", "ExHome")},
		[]Scan{listScan(1, "was/1.1", "VULNERABILITY", "SCHEDULED", "9001",
			"Example Homepage", "", "FINISHED", "NONE", day(1))},
		window, "")
	if rec.Matched != 1 || len(got) != 1 {
		t.Fatalf("matched %d, got %d results", rec.Matched, len(got))
	}
	r := got[0]
	if r.AppID != "9001" || r.App != "Example Homepage" {
		t.Errorf("identity not taken from the scan list: App=%q AppID=%q", r.App, r.AppID)
	}
	if r.AppState.Active.Serious != 2 {
		t.Error("the notification's counts were lost in the join")
	}
	if r.NoNotification {
		t.Error("a notified scan was flagged as having no notification")
	}
}

func TestTheApiCanMakeAScanWorseNeverBetter(t *testing.T) {
	// A FAILED authStatus is taken even when the email parse missed it.
	got, _ := Reconcile(
		[]appscan.ScanResult{fromMail("was/1.2", "ExPortal")},
		[]Scan{listScan(2, "was/1.2", "VULNERABILITY", "SCHEDULED", "9002",
			"Example Portal", "portal auth", "FINISHED", "FAILED", day(1))},
		window, "")
	if !got[0].Auth.Failed() {
		t.Errorf("an API-reported auth failure was dropped: %+v", got[0].Auth)
	}
	if got[0].Auth.Record != "portal auth" {
		t.Error("the failing credential's name was not carried, so the fault line cannot name it")
	}

	// And the other direction: the email says failed, the API says nothing
	// useful. It stays failed.
	m := fromMail("was/1.3", "ExPortal")
	m.Auth = appscan.Auth{Record: "portal auth", Status: "Failed"}
	got2, _ := Reconcile([]appscan.ScanResult{m},
		[]Scan{listScan(3, "was/1.3", "VULNERABILITY", "SCHEDULED", "9002",
			"Example Portal", "portal auth", "FINISHED", "SUCCESSFUL", day(1))},
		window, "")
	if !got2[0].Auth.Failed() {
		t.Error("the API overrode a notification's authentication failure with a success")
	}
}

func TestAScanWithNoEmailIsAddedWithoutCounts(t *testing.T) {
	got, _ := Reconcile(nil,
		[]Scan{listScan(4, "was/1.4", "VULNERABILITY", "SCHEDULED", "9004",
			"Example Store", "", "FINISHED", "NONE", day(2))},
		window, "")
	if len(got) != 1 || !got[0].NoNotification {
		t.Fatalf("an email-less vulnerability scan was not added as such: %+v", got)
	}
	if got[0].AppState.Active.Total() != 0 || got[0].ScanCounts.Total() != 0 {
		t.Error("counts were invented for a scan with no notification")
	}
	if got[0].Auth.Label() != "unauthenticated scan" {
		t.Errorf("Label = %q", got[0].Auth.Label())
	}
}

func TestDiscoveryAndRunningScansAreNotResults(t *testing.T) {
	// A discovery scan crawls and tests nothing; a running one has no result
	// yet. Neither belongs in a vulnerability report.
	got, rec := Reconcile(nil, []Scan{
		listScan(5, "was/1.5", "DISCOVERY", "ONDEMAND", "9005", "Staging", "x", "FINISHED", "FAILED", day(1)),
		listScan(6, "was/1.6", "VULNERABILITY", "SCHEDULED", "9006", "Site", "", "RUNNING", "", day(1)),
	}, window, "")
	if len(got) != 0 {
		t.Errorf("discovery or in-flight scans were reported: %+v", got)
	}
	if rec.Skipped != 2 {
		t.Errorf("Skipped = %d, want both counted", rec.Skipped)
	}
}

func TestAnOnDemandFaultWithNoEmailIsNotAScannerFault(t *testing.T) {
	// The real list had a run of on-demand scans against one staging
	// application while someone fixed its login. Raising each as a SCANNER
	// FAULT, and alerting the operator about their own test runs, is noise.
	got, rec := Reconcile(nil, []Scan{
		listScan(7, "was/1.7", "VULNERABILITY", "ONDEMAND", "9007", "Staging", "auth", "FINISHED", "FAILED", day(1)),
		listScan(8, "was/1.8", "VULNERABILITY", "ONDEMAND", "9007", "Staging", "", "CANCELED", "", day(1)),
	}, window, "")
	if len(got) != 0 || rec.Skipped != 2 {
		t.Errorf("on-demand faults were reported: got %d, skipped %d", len(got), rec.Skipped)
	}
}

func TestAScheduledAuthFailureWithNoEmailIsStillAFault(t *testing.T) {
	// The case that matters: authentication normally happens here, nobody is
	// watching it, and no email came to say it broke.
	got, _ := Reconcile(nil, []Scan{
		listScan(9, "was/1.9", "VULNERABILITY", "SCHEDULED", "9009", "Example Portal",
			"portal auth", "FINISHED", "FAILED", day(1)),
	}, window, "")
	if len(got) != 1 || !got[0].Fault() || !got[0].Auth.Failed() {
		t.Fatalf("a scheduled authentication failure was lost: %+v", got)
	}
}

func TestANewerEmaillessRunDoesNotDisplaceTheOneWithCounts(t *testing.T) {
	// Two runs of one application: the older with a notification, the newer
	// without. The application is reported from the scan we can describe.
	m := fromMail("was/1.10", "ExHome")
	got, _ := Reconcile([]appscan.ScanResult{m}, []Scan{
		listScan(10, "was/1.10", "VULNERABILITY", "SCHEDULED", "9001", "Example Homepage", "", "FINISHED", "NONE", day(1)),
		listScan(11, "was/1.11", "VULNERABILITY", "SCHEDULED", "9001", "Example Homepage", "", "FINISHED", "NONE", day(5)),
	}, window, "")
	if len(got) != 1 || got[0].NoNotification {
		t.Errorf("the email-less run was added beside or instead of the notified one: %+v", got)
	}
}

func TestTheMarginWidensTheJoinNotTheReport(t *testing.T) {
	// Launched a day before the window, finished inside it: the email is in
	// the mailbox window and must still match. An email-less scan launched
	// before the window must NOT be added.
	early := day(-1)
	got, rec := Reconcile([]appscan.ScanResult{fromMail("was/1.12", "ExHome")}, []Scan{
		listScan(12, "was/1.12", "VULNERABILITY", "SCHEDULED", "9001", "Example Homepage", "", "FINISHED", "NONE", early),
		listScan(13, "was/1.13", "VULNERABILITY", "SCHEDULED", "9013", "Example Other", "", "FINISHED", "NONE", early),
	}, window, "")
	if rec.Matched != 1 {
		t.Error("a scan launched just before the window did not match its notification")
	}
	if len(got) != 1 {
		t.Errorf("an email-less scan from before the window was added: %+v", got)
	}
}

func TestANotificationTheListLacksIsKeptAndReported(t *testing.T) {
	got, rec := Reconcile([]appscan.ScanResult{fromMail("was/9.99", "ExHome")}, nil, window, "")
	if len(got) != 1 || got[0].AppState.Active.Serious != 2 {
		t.Error("an unmatched notification's counts were dropped")
	}
	if len(rec.Unmatched) != 1 || rec.Unmatched[0] != "was/9.99" {
		t.Errorf("Unmatched = %v", rec.Unmatched)
	}
}

const testPortal = "https://qualysguard.qg3.apps.qualys.com"

func TestEveryListedScanGetsALinkBuiltFromItsId(t *testing.T) {
	got, _ := Reconcile([]appscan.ScanResult{fromMail("was/1.20", "ExHome")}, []Scan{
		listScan(20, "was/1.20", "VULNERABILITY", "SCHEDULED", "9001", "Example Homepage", "", "FINISHED", "NONE", day(1)),
		listScan(21, "was/1.21", "VULNERABILITY", "SCHEDULED", "9021", "Example Store", "", "FINISHED", "NONE", day(2)),
	}, window, testPortal)
	want := map[string]string{
		"Example Homepage": testPortal + "/was/#/reports/online-reports/email-report/scan/20",
		"Example Store":    testPortal + "/was/#/reports/online-reports/email-report/scan/21",
	}
	for _, r := range got {
		if r.PortalURL != want[r.App] {
			t.Errorf("%s: PortalURL = %q, want %q", r.App, r.PortalURL, want[r.App])
		}
	}
}

func TestNoPortalMeansNoBuiltLink(t *testing.T) {
	got, _ := Reconcile([]appscan.ScanResult{fromMail("was/1.22", "ExHome")}, []Scan{
		listScan(22, "was/1.22", "VULNERABILITY", "SCHEDULED", "9001", "Example Homepage", "", "FINISHED", "NONE", day(1)),
	}, window, "")
	if got[0].PortalURL != "" {
		t.Errorf("a link was built with no portal configured: %q", got[0].PortalURL)
	}
}
