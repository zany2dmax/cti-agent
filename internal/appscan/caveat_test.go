package appscan

import (
	"strings"
	"testing"
	"time"
)

// A scan that finished with Service Errors Detected (decided 2026-11-10):
// sent to its owner, not held, and every place that shows it says it may be
// incomplete. The caveat text itself comes from the qualys package.

const testCaveat = "The scanner hit errors during this scan."

func TestACaveatScanIsSentNotHeld(t *testing.T) {
	fin := time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC)
	scans := []ScanResult{{App: "Partial", AppID: "101", Reference: "was/2.1", Complete: true,
		Caveat: testCaveat, Finished: fin, Auth: Auth{Record: "login", Status: "Successful"}}}
	f := BuildDeliveries(scans, deliverOwners(t), DeliveredLog{}, fin)
	if len(f.Deliveries) != 1 || f.Deliveries[0].Hold != "" || f.Deliveries[0].Caveat != testCaveat {
		t.Fatalf("got %+v", f.Deliveries)
	}
}

func TestTheOwnerMailSaysTheScanMayBeIncomplete(t *testing.T) {
	d := Delivery{App: "Partial", Caveat: testCaveat}
	h := RenderOwnerMail(d, "r.html", "").HTML
	if !strings.Contains(h, "The scan may be incomplete.") || !strings.Contains(h, testCaveat) {
		t.Error("the caveat is not in the owner email")
	}
	// Nothing open, but not the green of a clean scan.
	if strings.Contains(h, "border-left:4px solid #2f855a") {
		t.Error("a scan with errors and nothing found is shown as clean")
	}
	if strings.Contains(RenderOwnerMail(Delivery{App: "Clean"}, "r.html", "").HTML, "may be incomplete") {
		t.Error("a scan with no caveat says it may be incomplete")
	}
}

func TestTheOwnerReportSaysTheScanMayBeIncomplete(t *testing.T) {
	in := sampleOwnerReport()
	in.Findings = nil
	in.Delivery.Caveat = testCaveat
	out := string(RenderOwnerReport(in))
	for _, want := range []string{"Scan result", "May be incomplete", testCaveat,
		"No vulnerabilities were found, but the scan hit errors."} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(out, "No vulnerabilities are open.") {
		t.Error("the report calls a scan with errors clean")
	}
}

func TestTheWeeklyListsACaveatScanAndStillCountsIt(t *testing.T) {
	s := publicScan()
	s.Caveat = testCaveat
	b := render(t, s)
	if !strings.Contains(b.Text, "finished with service errors") || !strings.Contains(b.Text, testCaveat) {
		t.Errorf("the weekly does not flag the scan:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "OPEN NOW") {
		t.Errorf("the scan's findings were dropped from OPEN NOW:\n%s", b.Text)
	}
}
