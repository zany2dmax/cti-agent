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

// withHosts restores the package's host lists after a test that changes them.
func withHosts(t *testing.T) {
	t.Helper()
	r, p := append([]string(nil), ReportHosts...), append([]string(nil), PortalHosts...)
	t.Cleanup(func() { ReportHosts, PortalHosts = r, p })
}

func TestUsePlatformAddsTheOperatorsPlatform(t *testing.T) {
	withHosts(t)
	us := len(PortalHosts)
	eu := "https://qualysapi.qg2.apps.qualys.eu"
	if PortalOrigin(eu) != "" {
		t.Fatal("an EU pod had a link before it was configured")
	}
	if err := UsePlatform(eu, "qualysguard.qualys.ca, qualysguard.qg1.apps.qualys.in"); err != nil {
		t.Fatal(err)
	}
	if got := PortalOrigin(eu); got != "https://qualysguard.qg2.apps.qualys.eu" {
		t.Errorf("PortalOrigin(EU) = %q", got)
	}
	if got, err := UnwrapReportLink("https://qualysguard.qg2.apps.qualys.eu/was/#/reports/x"); err != nil || got == "" {
		t.Errorf("an EU report link was refused: %q %v", got, err)
	}
	for _, h := range []string{"qualysguard.qualys.ca", "qualysguard.qg1.apps.qualys.in", "qualysapi.qg2.apps.qualys.eu"} {
		found := false
		for _, x := range ReportHosts {
			found = found || x == h
		}
		if !found {
			t.Errorf("%s not accepted for report links", h)
		}
	}
	// The US pods are still there: a box on one behaves as before.
	if PortalOrigin("https://qualysapi.qg3.apps.qualys.com") == "" || len(PortalHosts) != us+3 {
		t.Errorf("US pods changed: %v", PortalHosts)
	}
	// Twice is the same as once.
	_ = UsePlatform(eu, "qualysguard.qualys.ca")
	if len(PortalHosts) != us+3 {
		t.Errorf("hosts added twice: %v", PortalHosts)
	}
}

func TestUsePlatformRefusesAnythingButAHostName(t *testing.T) {
	withHosts(t)
	before := len(ReportHosts)
	for _, bad := range []string{"*.qualys.eu", "https://qualysguard.qualys.eu", "qualysguard.qualys.eu:443",
		"qualysguard.qualys.eu/x", "localhost", "qualys.eu", "qualys guard.eu"} {
		if err := UsePlatform("https://qualysapi.qg2.apps.qualys.eu", bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// Refused means nothing added, not even the base URL's own host.
	if len(ReportHosts) != before {
		t.Errorf("a refused list still added hosts: %v", ReportHosts)
	}
	// A base URL that is not https, or not an API host, adds nothing.
	for _, base := range []string{"http://qualysapi.qg2.apps.qualys.eu", "https://example.com", "not a url"} {
		if err := UsePlatform(base, ""); err != nil || len(ReportHosts) != before {
			t.Errorf("UsePlatform(%q) added %v (%v)", base, ReportHosts, err)
		}
	}
}
