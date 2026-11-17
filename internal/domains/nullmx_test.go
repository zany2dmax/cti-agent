package domains

import (
	"strings"
	"testing"
)

// mxAction is the MX change proposed for a domain, if any.
func mxAction(t *testing.T, acts []Action, domain string) (Action, bool) {
	t.Helper()
	for _, a := range acts {
		if a.Domain == domain && a.Type == "MX" {
			return a, true
		}
	}
	return Action{}, false
}

// A "no mail" domain (no markers) whose MX is on the gateway.
func noMail(name string, mx ...string) Result {
	return Result{Entry: Entry{Name: name}, Mail: Mail{MX: Lookup{Values: mx}}}
}

func received(m map[string]int, known bool) *GatewayStatus {
	gw := evidence(nil, nil, true)
	gw.Evidence.Received, gw.Evidence.ReceivedKnown = m, known
	if !known {
		gw.Evidence.ReceivedWhy = "none of the 4 inbound and internal events carried a recipient"
	}
	return gw
}

func TestNullMXIsReviewedForADomainThatReceivesMail(t *testing.T) {
	results := []Result{
		noMail("busy.example", "mxa-1.gslb.pphosted.com", "mxb-1.gslb.pphosted.com"),
		noMail("quiet.example", "mxa-1.gslb.pphosted.com"),
	}
	// Mail to a subdomain does not count for the apex.
	gw := received(map[string]int{"busy.example": 12, "sub.quiet.example": 3}, true)
	acts := ActionsWith(results, "", gw)

	busy, ok := mxAction(t, acts, "busy.example")
	if !ok || busy.Exact() || busy.Set != "" {
		t.Fatalf("a domain that received mail must get a review item, not a null MX: %+v", busy)
	}
	if !strings.Contains(busy.Why, "delivered 12 message(s)") || busy.Replace == "" {
		t.Errorf("the review item must give the count and the current MX: %+v", busy)
	}
	quiet, ok := mxAction(t, acts, "quiet.example")
	if !ok || !quiet.Exact() || quiet.Set != "0 ." || !strings.Contains(quiet.Why, "delivered no mail to it in 7 days") {
		t.Errorf("a domain the gateway delivered nothing to keeps its exact null MX: %+v", quiet)
	}
	// The other lock-down changes for the busy domain are untouched.
	var spf bool
	for _, a := range acts {
		spf = spf || (a.Domain == "busy.example" && a.Host == "@" && a.Type == "TXT" && a.Exact())
	}
	if !spf {
		t.Error("only the MX change moves to review; SPF stays exact")
	}
}

func TestNullMXIsReviewedWhenTheLogHasNoRecipients(t *testing.T) {
	results := []Result{noMail("quiet.example", "mxa-1.gslb.pphosted.com")}
	a, ok := mxAction(t, ActionsWith(results, "", received(nil, false)), "quiet.example")
	if !ok || a.Exact() || !strings.Contains(a.Why, "could not tell whether mail arrives") {
		t.Fatalf("no recipient data must fail closed: %+v", a)
	}
	var medium bool
	for _, f := range EvalGateway(results, received(nil, false)) {
		medium = medium || (f.Domain == gatewayFinding && f.Sev == Medium && strings.Contains(f.Text, "null MX"))
	}
	if !medium {
		t.Error("the report must say the null MX changes were moved to review")
	}
}

func TestNullMXOffTheGatewayIsMarkedNotChecked(t *testing.T) {
	results := []Result{noMail("m365.example", "m365-example.mail.protection.outlook.com")}
	a, ok := mxAction(t, ActionsWith(results, "", received(map[string]int{}, true)), "m365.example")
	if !ok || !a.Exact() || !strings.Contains(a.Why, "not checked against the mail gateway") {
		t.Errorf("an MX the gateway does not see must say it was not checked: %+v", a)
	}
	// Mail the gateway did deliver (an internal relay, say) still counts.
	a, _ = mxAction(t, ActionsWith(results, "", received(map[string]int{"m365.example": 2}, true)), "m365.example")
	if a.Exact() {
		t.Errorf("delivered mail is evidence wherever the MX points: %+v", a)
	}
}

func TestNullMXWithoutAnMXTodayIsNotGated(t *testing.T) {
	results := []Result{noMail("bare.example")}
	a, ok := mxAction(t, ActionsWith(results, "", received(nil, false)), "bare.example")
	if !ok || !a.Exact() || strings.Contains(a.Why, "gateway") {
		t.Errorf("with no MX there is no mail path to break: %+v", a)
	}
}

func TestNullMXWithoutAGatewayIsUnchanged(t *testing.T) {
	results := []Result{noMail("busy.example", "mxa-1.gslb.pphosted.com")}
	a, _ := mxAction(t, Actions(results, ""), "busy.example")
	if !a.Exact() || strings.Contains(a.Why, "gateway") {
		t.Errorf("no gateway configured must change nothing: %+v", a)
	}
}

func TestEvalGatewayNamesANoMailDomainThatReceives(t *testing.T) {
	results := []Result{noMail("busy.example", "mxa-1.gslb.pphosted.com")}
	var high bool
	for _, f := range EvalGateway(results, received(map[string]int{"busy.example": 5}, true)) {
		high = high || (f.Domain == "busy.example" && f.Sev == High && strings.Contains(f.Text, "receives no mail"))
	}
	if !high {
		t.Error("expected a High finding for a no-mail domain that received mail")
	}
}
