package qualys

import "testing"

func TestThePortalOriginComesFromTheApiHost(t *testing.T) {
	// A pod this code does not know gets no link rather than a guessed one,
	// and plain http never becomes a link.
	for base, want := range map[string]string{
		"https://qualysapi.qg3.apps.qualys.com":  "https://qualysguard.qg3.apps.qualys.com",
		"https://qualysapi.qg1.apps.qualys.com/": "https://qualysguard.qg1.apps.qualys.com",
		"https://qualysapi.qg9.apps.qualys.com":  "",
		"https://qualysapi.example.com":          "",
		"http://qualysapi.qg3.apps.qualys.com":   "",
		"":                                       "",
	} {
		if got := PortalOrigin(base); got != want {
			t.Errorf("PortalOrigin(%q) = %q, want %q", base, got, want)
		}
	}
}

func TestTheScanReportUrlIsTheOneQualysMails(t *testing.T) {
	// The path and the id were checked against a real completion email: its
	// "view these scan results" link carries the scan list's <id>.
	got := ScanReportURL("https://qualysguard.qg3.apps.qualys.com", 25000001)
	want := "https://qualysguard.qg3.apps.qualys.com/was/#/reports/online-reports/email-report/scan/25000001"
	if got != want {
		t.Errorf("ScanReportURL = %q, want %q", got, want)
	}
	if ScanReportURL("", 1) != "" || ScanReportURL("https://qualysguard.qg3.apps.qualys.com", 0) != "" {
		t.Error("a link was built without an origin or an id")
	}
}
