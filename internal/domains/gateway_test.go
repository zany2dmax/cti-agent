package domains

import (
	"strings"
	"testing"
	"time"
)

func res(name string, e Entry) Result {
	e.Name = name
	return Result{Entry: e}
}

func evidence(out map[string]int, in map[string]InboundClaim, complete bool) *GatewayStatus {
	since := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	return &GatewayStatus{Enabled: true, Evidence: &GatewayEvidence{
		Gateway: "Test gateway", Since: since, To: since.Add(7 * 24 * time.Hour),
		Complete: complete, Events: 100, Outbound: out, Inbound: in}}
}

func TestGatewayWindow(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 34, 0, 0, time.UTC)
	since, to := GatewayWindow(now, 7)
	if !to.Equal(time.Date(2026, 11, 3, 11, 0, 0, 0, time.UTC)) || to.Sub(since) != 7*24*time.Hour {
		t.Errorf("%v %v", since, to)
	}
	if to.After(now.Add(-time.Hour)) {
		t.Error("the window must end more than an hour ago")
	}
	if s, e := GatewayWindow(now, 99); e.Sub(s) != 28*24*time.Hour {
		t.Errorf("days are capped at 28: %v", e.Sub(s))
	}
}

func TestActionsWithGateway(t *testing.T) {
	m := Mail{SPF: Lookup{Values: []string{"v=spf1 include:x.example ~all"}}}
	a := Result{Entry: Entry{Name: "locked.example", Receives: true}, Mail: m}
	b := Result{Entry: Entry{Name: "quiet.example", Receives: true}, Mail: m}
	results := []Result{a, b}

	if n := len(Actions(results, "")); n == 0 {
		t.Fatal("precondition: lock-down actions expected with no gateway")
	}
	if n := len(ActionsWith(results, "", &GatewayStatus{})); n == 0 {
		t.Error("a disabled gateway must change nothing")
	}
	// Evidence: locked.example sends; quiet.example does not.
	gw := evidence(map[string]int{"locked.example": 3, "mail.locked.example": 1}, nil, true)
	for _, x := range ActionsWith(results, "", gw) {
		if x.Domain == "locked.example" {
			t.Errorf("a domain with outbound mail was asked to lock down: %+v", x)
		}
	}
	got := ActionsWith(results, "", gw)
	if len(got) == 0 || got[0].Domain != "quiet.example" {
		t.Errorf("the quiet domain should still be locked down: %+v", got)
	}
	// Incomplete or failed evidence holds every lock-down.
	for _, g := range []*GatewayStatus{
		evidence(nil, nil, false),
		{Enabled: true, Err: "HTTP 409"},
	} {
		if n := len(ActionsWith(results, "", g)); n != 0 {
			t.Errorf("held gateway still produced %d action(s)", n)
		}
		if !g.Held() || g.HeldWhy() == "" {
			t.Errorf("Held/HeldWhy: %v %q", g.Held(), g.HeldWhy())
		}
	}
}

func TestEvalGateway(t *testing.T) {
	results := []Result{
		res("locked.example", Entry{Receives: true}),
		res("sender.example", Entry{Sends: true, Receives: true}),
		res("idle.example", Entry{Sends: true}),
		res("app.example", Entry{Sends: true, SaaS: true}),
	}
	gw := evidence(
		map[string]int{"locked.example": 2, "sender.example": 50, "stranger.example": 4,
			"tenant.onmicrosoft.com": 1, "(none)": 9},
		map[string]InboundClaim{"sender.example": {Total: 10, Pass: 9}}, true)
	var text []string
	sev := map[string]Severity{}
	for _, f := range EvalGateway(results, gw) {
		text = append(text, f.Domain+": "+f.Text)
		sev[f.Domain+"/"+f.Text[:12]] = f.Sev
	}
	all := strings.Join(text, "\n")
	for _, want := range []string{
		"locked.example: the inventory says this domain sends nothing",
		"stranger.example: 4 outbound message(s)",
		"idle.example: marked as sending, but the gateway saw no outbound mail",
		"sender.example: 7 days of inbound mail used this domain in the From address: 10 message(s), 9 passed DMARC, 1 did not",
		"(mail gateway): Test gateway log",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	for _, unwanted := range []string{"onmicrosoft", "(none): ", "app.example"} {
		if strings.Contains(all, unwanted) {
			t.Errorf("%q must not be reported:\n%s", unwanted, all)
		}
	}
	for _, f := range EvalGateway(results, gw) {
		if f.Domain == "locked.example" && f.Sev != High {
			t.Errorf("a locked-down domain that sends must be High: %v", f.Sev)
		}
	}
	if got := EvalGateway(results, nil); got != nil {
		t.Error("no gateway, no findings")
	}
	held := EvalGateway(results, &GatewayStatus{Enabled: true, Err: "HTTP 409"})
	if len(held) != 1 || held[0].Sev != Medium || !strings.Contains(held[0].Text, "no Jira ticket is filed") {
		t.Errorf("held: %+v", held)
	}
}

func TestInboundPassAsLockedDomainSkipsLockdown(t *testing.T) {
	m := Mail{SPF: Lookup{Values: []string{"v=spf1 include:x.example ~all"}}}
	results := []Result{{Entry: Entry{Name: "service.example", Receives: true}, Mail: m}}
	gw := evidence(nil, map[string]InboundClaim{"service.example": {Total: 5, Pass: 5}}, true)
	acts, skipped := ActionsWithSkipped(results, "", gw)
	if len(acts) != 0 || len(skipped) != 1 || skipped[0] != "service.example" {
		t.Fatalf("acts=%v skipped=%v", acts, skipped)
	}
	var high bool
	for _, f := range EvalGateway(results, gw) {
		high = high || (f.Domain == "service.example" && f.Sev == High && strings.Contains(f.Text, "PASSED DMARC"))
	}
	if !high {
		t.Error("expected a High finding naming the passing service")
	}
}
