package domains

import (
	"strings"
	"testing"
)

func spfResult(name, spf string) Result {
	return Result{Entry: Entry{Name: name, Sends: true},
		Mail: Mail{SPF: Lookup{Values: []string{spf}}}}
}

func TestSPFListedByAddressCountsAsProofpointOnDemand(t *testing.T) {
	// The admin's case: the include would push the record over SPF's 10-lookup
	// limit, so the two PoD addresses are listed directly.
	t.Setenv("PROOFPOINT_POD_TENANT", "")
	t.Setenv("PROOFPOINT_POD_IPS", "148.163.143.101, 148.163.147.152")
	r := podDomain("a.example.com", true,
		"v=spf1 ip4:148.163.143.101 ip4:148.163.147.152 include:spf.protection.outlook.com -all")
	if rt := RouteOf(r, ours); !rt.SPFPoD {
		t.Fatal("SPF that lists the PoD addresses was not read as authorising PoD")
	}
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	for _, f := range EvalProofpoint([]Result{r}, nil, now) {
		if strings.Contains(f.Text, "does not authorise Proofpoint") {
			t.Errorf("a domain that lists the addresses was reported as not authorising Proofpoint: %s", f.Text)
		}
	}

	// Another address, or no setting, does not.
	other := podDomain("b.example.com", true, "v=spf1 ip4:203.0.113.9 -all")
	if RouteOf(other, ours).SPFPoD {
		t.Error("an unrelated address was read as Proofpoint")
	}
	t.Setenv("PROOFPOINT_POD_IPS", "")
	if RouteOf(r, ours).SPFPoD {
		t.Error("without PROOFPOINT_POD_IPS the addresses must mean nothing")
	}
}

func TestAPodAddressRangeMustLieInsideTheListedOne(t *testing.T) {
	pod := podIPs()
	if len(pod) != 0 {
		t.Skip("environment sets PROOFPOINT_POD_IPS")
	}
	t.Setenv("PROOFPOINT_POD_IPS", "148.163.128.0/19")
	pod = podIPs()
	for mech, want := range map[string]bool{
		"ip4:148.163.143.101":  true,
		"ip4:148.163.140.0/24": true,
		"ip4:148.163.0.0/16":   false, // wider than what is listed
		"ip4:8.8.8.8":          false,
		"include:foo.example":  false,
		"ip4:not-an-address":   false,
		"-ip4:148.163.143.101": true,
	} {
		if got := isPoDIP(mech, pod); got != want {
			t.Errorf("isPoDIP(%q) = %v, want %v", mech, got, want)
		}
	}
}

func TestSPFIncludesNameTheVendor(t *testing.T) {
	t.Setenv("PROOFPOINT_POD_IPS", "148.163.143.101")
	t.Setenv("DOMAINS_SPF_VENDORS", "")
	rs := []Result{
		spfResult("a.example.com", "v=spf1 include:spf.smtp2go.com include:_phishspf.knowbe4.com ip4:148.163.143.101 -all"),
		spfResult("b.example.com", "v=spf1 include:spf.smtp2go.com include:mystery.example.net -all"),
	}
	got := map[string]SPFInclude{}
	for _, x := range SPFIncludes(rs) {
		got[x.Mechanism] = x
	}
	if x := got["include:spf.smtp2go.com"]; !strings.Contains(x.Vendor, "SMTP2GO") || len(x.Domains) != 2 {
		t.Errorf("smtp2go: %+v", x)
	}
	if x := got["include:_phishspf.knowbe4.com"]; !strings.Contains(x.Vendor, "KnowBe4") {
		t.Errorf("knowbe4: %+v", x)
	}
	if x := got["ip4:148.163.143.101"]; !strings.Contains(x.Vendor, "Proofpoint on Demand") {
		t.Errorf("pod address: %+v", x)
	}
	if x := got["include:mystery.example.net"]; x.Vendor != "" {
		t.Errorf("an unknown include was given a vendor: %+v", x)
	}
	// The ones nobody has identified come first.
	if first := SPFIncludes(rs)[0]; first.Mechanism != "include:mystery.example.net" {
		t.Errorf("first = %s, want the unrecognised include", first.Mechanism)
	}
}

func TestTheOperatorCanNameAnUnrecognisedInclude(t *testing.T) {
	t.Setenv("DOMAINS_SPF_VENDORS", "mystery.example.net=Acme Surveys - HR survey mail, spf.smtp2go.com=Old relay (retire)")
	if w, ok := SPFVendor("mystery.example.net"); !ok || !strings.Contains(w, "Acme Surveys") {
		t.Errorf("custom vendor: %q %v", w, ok)
	}
	// And overrides the built-in text.
	if w, _ := SPFVendor("spf.smtp2go.com"); !strings.Contains(w, "Old relay") {
		t.Errorf("override ignored: %q", w)
	}
	// Suffix match is on a label boundary.
	if _, ok := SPFVendor("notsmtp2go.com"); ok {
		t.Error("notsmtp2go.com matched smtp2go.com")
	}
}

func TestTheReportListsIncludesInBothForms(t *testing.T) {
	t.Setenv("DOMAINS_SPF_VENDORS", "")
	t.Setenv("PROOFPOINT_POD_IPS", "")
	rep := Report{Results: []Result{
		spfResult("a.example.com", "v=spf1 include:spf.smtp2go.com include:mystery.example.net -all"),
	}}
	txt := rep.text()
	for _, want := range []string{SPFVendorsTitle, "include:spf.smtp2go.com", "SMTP2GO",
		"NOT RECOGNISED - find out who this is"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text report lacks %q", want)
		}
	}
	if h := rep.html(); !strings.Contains(h, "SMTP2GO") || !strings.Contains(h, "NOT RECOGNISED") {
		t.Error("HTML report lacks the include descriptions")
	}
	if d := spfDescribed(rep.Results[0]); !strings.Contains(d, "include:spf.smtp2go.com = SMTP2GO") {
		t.Errorf("csv column = %q", d)
	}
}
