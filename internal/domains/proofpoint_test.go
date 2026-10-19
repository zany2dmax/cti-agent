package domains

import (
	"strings"
	"testing"
	"time"
)

// Tenant ids and hosts are invented. The real ones identify the organisation,
// and this repository is public.
const (
	ours   = "00aa1111"
	theirs = "00bb2222"
)

func podDomain(name string, sends bool, spf string) Result {
	return Result{
		Entry: Entry{Name: name, Sends: sends, Receives: true},
		Mail: Mail{
			MX:  Lookup{Values: []string{"mx0a-" + ours + ".pphosted.com", "mx0b-" + ours + ".pphosted.com"}},
			SPF: Lookup{Values: []string{spf}},
		},
	}
}

func routed(name string, sends bool, mx []string, spf string) Result {
	r := Result{Entry: Entry{Name: name, Sends: sends, Receives: true},
		Mail: Mail{SPF: Lookup{Values: []string{spf}}}}
	if len(mx) == 0 {
		r.Mail.MX = Lookup{Absent: true}
	} else {
		r.Mail.MX = Lookup{Values: mx}
	}
	return r
}

func TestTheTenantIsTheMostCommonOneOnePerDomain(t *testing.T) {
	t.Setenv("PROOFPOINT_POD_TENANT", "")
	rs := []Result{
		podDomain("a.example.com", true, "v=spf1 include:spf-"+ours+".pphosted.com -all"),
		podDomain("b.example.com", true, "v=spf1 -all"),
		routed("c.example.com", false, []string{"mx0a-" + theirs + ".pphosted.com",
			"mx0b-" + theirs + ".pphosted.com", "mx0c-" + theirs + ".pphosted.com"}, ""),
	}
	if got := HomeTenant(rs); got != ours {
		t.Errorf("HomeTenant = %q, want %q - three MX hosts are still one domain's vote", got, ours)
	}
	t.Setenv("PROOFPOINT_POD_TENANT", theirs)
	if got := HomeTenant(rs); got != theirs {
		t.Errorf("the pin was ignored: %q", got)
	}
}

func TestNoProofpointAnywhereSwitchesTheCheckOff(t *testing.T) {
	t.Setenv("PROOFPOINT_POD_TENANT", "")
	rs := []Result{routed("a.example.com", true,
		[]string{"a-example-com.mail.protection.outlook.com"}, "v=spf1 include:spf.protection.outlook.com -all")}
	tenant := HomeTenant(rs)
	AssignRoutes(rs, tenant)
	if tenant != "" || rs[0].RouteChecked {
		t.Errorf("tenant %q, checked %v: a fleet without PoD must not grow a PoD section", tenant, rs[0].RouteChecked)
	}
	if f := EvalProofpoint(rs, nil, time.Now()); len(f) != 0 {
		t.Errorf("findings without PoD: %v", f)
	}
}

func TestADomainOnTheGatewayIsQuiet(t *testing.T) {
	r := podDomain("a.example.com", true, "v=spf1 include:spf-"+ours+".pphosted.com -all")
	rt := RouteOf(r, ours)
	if rt.Inbound != "pod" || !rt.SPFPoD || rt.State() != "pod" {
		t.Fatalf("route = %+v", rt)
	}
	r.Route, r.RouteChecked = rt, true
	if f := EvalProofpoint([]Result{r}, nil, time.Now()); len(f) != 0 {
		t.Errorf("a domain fully on PoD produced findings: %v", f)
	}
}

func TestAnAcquisitionNotYetMovedIsNamedWithItsProvider(t *testing.T) {
	cases := []struct {
		mx, spf, want string
	}{
		{"acq-example-com.mail.protection.outlook.com", "v=spf1 include:spf.protection.outlook.com -all", "Microsoft 365 directly"},
		{"aspmx.l.google.com", "v=spf1 include:_spf.google.com ~all", "Google Workspace"},
		{"eu-smtp-inbound-1.mimecast.com", "v=spf1 include:eu._netblocks.mimecast.com -all", "Mimecast"},
		{"mail.acq.example.net", "v=spf1 mx -all", "an unrecognised mail host"},
	}
	for _, c := range cases {
		r := routed("acq.example.com", true, []string{c.mx}, c.spf)
		r.Route, r.RouteChecked = RouteOf(r, ours), true
		f := EvalProofpoint([]Result{r}, nil, time.Now())
		var text []string
		for _, x := range f {
			text = append(text, x.Text)
		}
		all := strings.Join(text, " | ")
		if !strings.Contains(all, "NOT YET ON PROOFPOINT") || !strings.Contains(all, c.want) {
			t.Errorf("%s: %s", c.mx, all)
		}
		if !strings.Contains(all, "send route unconfirmed") {
			t.Errorf("%s: a sender not authorising PoD must say so: %s", c.mx, all)
		}
	}
}

func TestAnotherOrganisationsTenantIsHigh(t *testing.T) {
	r := routed("x.example.com", false, []string{"mx0a-" + theirs + ".pphosted.com"}, "v=spf1 -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	f := EvalProofpoint([]Result{r}, nil, time.Now())
	if len(f) != 1 || f[0].Sev != High || !strings.Contains(f[0].Text, theirs) {
		t.Errorf("findings = %+v", f)
	}
}

func TestLeftoversAfterTheMoveAreFlagged(t *testing.T) {
	r := podDomain("moved.example.com", true,
		"v=spf1 include:spf-"+ours+".pphosted.com include:spf.protection.outlook.com include:sendgrid.net -all")
	r.Mail.DKIM.Found = []string{"selector1", "google"}
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	f := EvalProofpoint([]Result{r}, nil, time.Now())
	all := ""
	for _, x := range f {
		all += x.Text + " | "
	}
	if !strings.Contains(all, "also authorises Microsoft 365 directly") {
		t.Errorf("the M365 include was not noted: %s", all)
	}
	for _, x := range f {
		if strings.Contains(x.Text, "Microsoft 365") && x.Sev != Info {
			t.Errorf("M365 beside PoD is commonly deliberate; a note, not %s", x.Sev)
		}
	}
	if strings.Contains(all, "sendgrid") {
		t.Errorf("a SaaS sender beside PoD is legitimate, not a leftover: %s", all)
	}
	if !strings.Contains(all, "selector google") {
		t.Errorf("a Google DKIM key on a PoD domain was not flagged: %s", all)
	}
	if strings.Contains(all, "selector1") {
		t.Errorf("Microsoft's selectors are expected with PoD outbound: %s", all)
	}
}

func TestANullMXDomainIsNotListed(t *testing.T) {
	r := routed("parked.example.com", false, []string{"."}, "v=spf1 -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	if r.Route.Inbound != "none" {
		t.Errorf("null MX read as %q", r.Route.Inbound)
	}
	if f := EvalProofpoint([]Result{r}, nil, time.Now()); len(f) != 0 {
		t.Errorf("a locked-down domain was listed: %v", f)
	}
}

func TestHowLongItHasBeenOffTheGatewayCarriesAcrossWeeks(t *testing.T) {
	week1 := time.Date(2026, 9, 7, 7, 0, 0, 0, time.UTC)
	r := routed("acq.example.com", false, []string{"acq-example-com.mail.protection.outlook.com"}, "v=spf1 -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true

	s1 := Snap(week1, []Result{r}, nil, nil, nil)
	if s1.Domains["acq.example.com"].RouteSince != "2026-09-07" {
		t.Fatalf("first sighting not dated: %+v", s1.Domains["acq.example.com"])
	}
	week6 := week1.Add(5 * 7 * 24 * time.Hour)
	s6 := Snap(week6, []Result{r}, nil, nil, s1)
	f := EvalProofpoint([]Result{r}, s6, week6)
	if len(f) == 0 || !strings.Contains(f[0].Text, "for 5 weeks") {
		t.Errorf("findings = %+v", f)
	}

	// Moved to PoD: the clock restarts in the new state.
	moved := podDomain("acq.example.com", false, "v=spf1 -all")
	moved.Route, moved.RouteChecked = RouteOf(moved, ours), true
	s7 := Snap(week6.Add(7*24*time.Hour), []Result{moved}, nil, nil, s6)
	if got := s7.Domains["acq.example.com"]; got.Route == s6.Domains["acq.example.com"].Route {
		t.Errorf("route state did not change after the move: %+v", got)
	}
}

func TestAFailedLookupDoesNotLookLikeAMove(t *testing.T) {
	now := time.Date(2026, 9, 7, 7, 0, 0, 0, time.UTC)
	r := routed("acq.example.com", false, []string{"acq-example-com.mail.protection.outlook.com"}, "v=spf1 -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	s1 := Snap(now, []Result{r}, nil, nil, nil)

	broken := r
	broken.Mail.MX = Lookup{Err: "timeout"}
	broken.Route, broken.RouteChecked = RouteOf(broken, ours), true
	s2 := Snap(now.Add(7*24*time.Hour), []Result{broken}, nil, nil, s1)
	if s2.Domains["acq.example.com"].RouteSince != "2026-09-07" {
		t.Errorf("one failed lookup reset the clock: %+v", s2.Domains["acq.example.com"])
	}
}

func TestTheGatewaySectionRendersOnceAndCountsInTheSubject(t *testing.T) {
	r := routed("acq.example.com", false, []string{"acq-example-com.mail.protection.outlook.com"}, "v=spf1 -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	f := EvalProofpoint([]Result{r}, nil, time.Now())
	rep := Report{Now: time.Now(), Results: []Result{r}, Findings: f, Registrar: "GoDaddy"}
	b := rep.Render()
	for name, body := range map[string]string{"text": b.Text, "html": b.HTML} {
		if !strings.Contains(body, "NOT YET ON THE GATEWAY") {
			t.Errorf("%s: no gateway section", name)
		}
		if n := strings.Count(body, "outside the gateway"); n != 1 {
			t.Errorf("%s: the finding appears %d times, want once", name, n)
		}
	}
	if !strings.Contains(b.Subject, "1 Medium") {
		t.Errorf("subject %q: a finding in its own section must still count", b.Subject)
	}
}

func TestNoMajorityTenantSwitchesTheCheckOffRatherThanGuess(t *testing.T) {
	// An acquisition with as many PoD domains on its own tenant as we have
	// must not decide which tenant is "ours" - every one of our domains would
	// then read as another organisation's gateway.
	t.Setenv("PROOFPOINT_POD_TENANT", "")
	rs := []Result{
		podDomain("a.example.com", true, "v=spf1 -all"),
		routed("b.example.net", false, []string{"mx0a-" + theirs + ".pphosted.com"}, ""),
	}
	tenant, counts := HomeTenantWhy(rs)
	if tenant != "" || counts[ours] != 1 || counts[theirs] != 1 {
		t.Errorf("tenant %q counts %v: a tie must switch the check off", tenant, counts)
	}
}

func TestNestedSPFIncludesCountAsAuthorisingProofpoint(t *testing.T) {
	r := podDomain("sub.example.com", true, "v=spf1 include:_spf.example.com -all")
	r.Mail.SPFIncludes = []string{"_spf.example.com", "spf-" + ours + ".pphosted.com"}
	if rt := RouteOf(r, ours); !rt.SPFPoD {
		t.Errorf("PoD authorised through a parent record was missed: %+v", rt)
	}
}

func TestMixedTenantsAreAnotherOrganisationsGateway(t *testing.T) {
	r := routed("x.example.com", true, []string{"mx0a-" + ours + ".pphosted.com", "mx0b-" + theirs + ".pphosted.com"}, "v=spf1 -all")
	if rt := RouteOf(r, ours); rt.Inbound != "pod-other" {
		t.Errorf("mixed tenants read as %q", rt.Inbound)
	}
}

func TestAnOffGatewaySenderSaysWhatItSendsThrough(t *testing.T) {
	r := routed("acq.example.com", true, []string{"acq-example-com.mail.protection.outlook.com"},
		"v=spf1 include:spf.protection.outlook.com -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	for _, x := range EvalProofpoint([]Result{r}, nil, time.Now()) {
		if strings.Contains(x.Text, "send route unconfirmed") && !strings.Contains(x.Text, "Microsoft 365") {
			t.Errorf("the send line hides what SPF authorises: %s", x.Text)
		}
	}
}

func TestADomainThatReceivesNoMailIsNotListedTwice(t *testing.T) {
	// evalLockedMX already reports a stray MX on a no-mail domain.
	r := routed("parked.example.com", false, []string{"mailstore1.secureserver.net"}, "v=spf1 -all")
	r.Entry.Receives = false
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	for _, x := range EvalProofpoint([]Result{r}, nil, time.Now()) {
		if strings.Contains(x.Text, "NOT YET ON PROOFPOINT") {
			t.Errorf("reported twice: %s", x.Text)
		}
	}
}

func TestTheClockSurvivesAWeekWithTheCheckOff(t *testing.T) {
	now := time.Date(2026, 9, 7, 7, 0, 0, 0, time.UTC)
	r := routed("acq.example.com", false, []string{"acq-example-com.mail.protection.outlook.com"}, "v=spf1 -all")
	r.Route, r.RouteChecked = RouteOf(r, ours), true
	s1 := Snap(now, []Result{r}, nil, nil, nil)
	off := r
	off.RouteChecked = false
	s2 := Snap(now.Add(7*24*time.Hour), []Result{off}, nil, nil, s1)
	if s2.Domains["acq.example.com"].RouteSince != "2026-09-07" {
		t.Errorf("a week with the check off reset the clock: %+v", s2.Domains["acq.example.com"])
	}
}
