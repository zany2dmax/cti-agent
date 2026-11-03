package main

import (
	"strings"
	"testing"
)

// escalation is what the orchestrator sends: a healthy unit, a real message.
func escalation() failure {
	return failure{
		Kind: "ESCALATION", Unit: "cti-agent-checkin.service", Host: "host-a",
		Result: "success", ExitCode: "0", NRestarts: "0",
		Reason: "3 KEV-listed CVEs PRESENT and overdue",
	}
}

func TestAnEscalationIsNotPresentedAsAFailure(t *testing.T) {
	// The first real escalation this channel carried arrived titled "CTI
	// fleet failure" with "systemd result: success / exit status 0"
	// underneath - a crash report contradicting itself, carrying three KEV
	// CVEs fourteen days overdue. An alert that has to be decoded is one
	// people learn to skim, and this is the one that must not be.
	h := renderHTML(escalation())
	if strings.Contains(h, "CTI fleet failure") {
		t.Error("an escalation is titled as a failure")
	}
	if !strings.Contains(h, "CTI fleet escalation") {
		t.Error("the escalation banner is missing")
	}
	if !strings.Contains(h, "Nothing has failed") {
		t.Error("the body does not say nothing failed")
	}
	if strings.Contains(h, "before assuming it is harmless") {
		t.Error("the failure footer survived into an escalation")
	}

	txt := renderText(escalation())
	if !strings.Contains(txt, "Nothing has failed") {
		t.Error("the text part still reads as a failure")
	}
	if strings.Contains(txt, "failed on") {
		t.Errorf("the text part says the unit failed:\n%s", txt)
	}
}

func TestTheReasonSurvivesIntoBothParts(t *testing.T) {
	// The reason IS the message for an escalation. Losing it leaves an email
	// that says only that something happened.
	f := escalation()
	for name, body := range map[string]string{"html": renderHTML(f), "text": renderText(f)} {
		if !strings.Contains(body, "3 KEV-listed CVEs PRESENT and overdue") {
			t.Errorf("%s part dropped the reason", name)
		}
	}
}

func TestAnUnknownKindIsStillTreatedAsAFailure(t *testing.T) {
	// Deliberate. An unrecognised kind was always a broken call site; now it
	// can also be an agent inventing a word. Both should err toward alarming.
	f := escalation()
	f.Kind = "SOMETHING-NEW"
	if f.notFailure() {
		t.Error("an unknown kind was treated as benign")
	}
	if !strings.Contains(renderHTML(f), "CTI fleet failure") {
		t.Error("an unknown kind did not render as a failure")
	}
}

func TestARealFailureIsUnchanged(t *testing.T) {
	f := failure{
		Kind: "FAILED", Unit: "cti-agent-digest.service", Host: "h",
		Result: "exit-code", ExitCode: "1", NRestarts: "0",
	}
	h := renderHTML(f)
	if !strings.Contains(h, "CTI fleet failure") {
		t.Error("a real failure lost its banner")
	}
	if !strings.Contains(h, "before assuming it is harmless") {
		t.Error("a real failure lost its consequence line")
	}
	if f.notFailure() {
		t.Error("a real failure was classified as benign")
	}
}

func TestAHealthyUnitIsRecognisedWhateverSystemctlSaid(t *testing.T) {
	// systemctl show reports "" or "unknown" for a unit that has never
	// failed. Treating that as a crash is how a test of the alert path
	// manufactures the thing it is testing for.
	for _, result := range []string{"success", "", "unknown"} {
		f := failure{ExitCode: "0", Result: result}
		if !f.unitIsHealthy() {
			t.Errorf("Result=%q exit=0 was not recognised as healthy", result)
		}
	}
	if (failure{ExitCode: "1", Result: "exit-code"}).unitIsHealthy() {
		t.Error("a failed unit was reported healthy")
	}
	if (failure{ExitCode: "0", Result: "timeout"}).unitIsHealthy() {
		t.Error("a timeout was reported healthy")
	}
}

func TestBoardLineMatchesTheKind(t *testing.T) {
	for kind, want := range map[string]string{
		"FAILED":     "ERROR",
		"HOLD":       "INFO",
		"TEST":       "INFO",
		"ESCALATION": "INFO",
	} {
		level, msg := boardLine(failure{Kind: kind, Unit: "u.service", Host: "host-a", Reason: "why"})
		if level != want {
			t.Errorf("%s: level %s, want %s", kind, level, want)
		}
		if kind != "FAILED" && strings.Contains(msg, "failed") {
			t.Errorf("%s: board line says failed: %q", kind, msg)
		}
	}
}

func TestTheAlertOpensWithAPlainSentenceAboutTheProblem(t *testing.T) {
	f := failure{
		Kind: "FAILED", Unit: "cti-agent-digest.service", Host: "host-a",
		Result: "exit-code", ExitCode: "1", NRestarts: "0", IsDigest: true,
		Journal: "Nov 03 06:00:01 host-a cti-agent-digest[1]: starting\n" +
			"Nov 03 06:00:09 host-a cti-agent-digest[1]: graph: HTTP 403 Forbidden for mailbox\n" +
			"Nov 03 06:00:09 host-a systemd[1]: cti-agent-digest.service: Failed with result 'exit-code'.\n",
	}
	got := explain(f)
	for _, want := range []string{
		"The daily threat-intel digest", "exited with an error (status 1)",
		"lacks a permission", `HTTP 403 Forbidden for mailbox`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("explanation lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Failed with result") {
		t.Error("systemd's own bookkeeping line was quoted as the cause")
	}
	if strings.Contains(got, "Nov 03 06:00:09") {
		t.Error("the journal's date/host prefix was left on the quoted line")
	}

	// It sits between the headline and the journal, in both parts.
	for name, body := range map[string]string{"html": renderHTML(f), "text": renderText(f)} {
		i := strings.Index(body, "WHAT THIS MEANS")
		j := strings.Index(body, "JOURNAL LINES")
		if name == "text" {
			j = strings.Index(body, "journal lines:")
		}
		if i < 0 || j < 0 || i > j {
			t.Errorf("%s: WHAT THIS MEANS (%d) must come before the journal (%d)", name, i, j)
		}
	}
}

func TestAHoldAndAnEscalationLeadWithTheirOwnMessage(t *testing.T) {
	h := failure{Kind: "HOLD", Unit: "cti-agent-scout.service", Reason: "beat budget used"}
	if got := explain(h); !strings.Contains(got, "stopped itself on purpose: beat budget used") {
		t.Errorf("hold: %s", got)
	}
	if got := explain(escalation()); !strings.HasPrefix(got, "The orchestrator needs you") ||
		!strings.Contains(got, "3 KEV-listed CVEs") {
		t.Errorf("escalation: %s", got)
	}
}

func TestTheExplanationSaysSoWhenTheJournalCannotBeRead(t *testing.T) {
	f := failure{Kind: "FAILED", Unit: "cti-agent-mailbox.service", Result: "timeout",
		ExitCode: "1", Journal: "(journal unavailable: exit status 1)"}
	got := explain(f)
	if !strings.Contains(got, "ran past its time limit") || !strings.Contains(got, "could not be read") {
		t.Errorf("got: %s", got)
	}
}

func TestTheHTMLExplanationIsEscaped(t *testing.T) {
	// The quoted line comes from a journal that can carry somebody else's
	// subject line.
	f := failure{Kind: "FAILED", Unit: "u.service", Result: "exit-code", ExitCode: "1",
		Journal: "Nov 03 06:00:09 h t[1]: error: <script>alert(1)</script>"}
	if strings.Contains(renderHTML(f), "<script>alert(1)") {
		t.Error("journal text reached the HTML unescaped")
	}
}

func TestOnlyTheFleetsOwnUnitsAreAccepted(t *testing.T) {
	for _, ok := range []string{
		"cti-agent-digest.service", "cti-agent-checkin.service",
		"cti-agent-alert@cti-agent-weekly.service.service",
	} {
		if !fleetUnit.MatchString(ok) {
			t.Errorf("%q refused, want accepted", ok)
		}
	}
	// An option systemctl would act on, a unit outside the fleet, and the
	// syntax that could smuggle either in.
	for _, bad := range []string{
		"", "--host=user@example.com", "-H", "--machine=x", "sshd.service",
		"cti-agent-", "cti-agent-x --host=y", "cti-agent-x=y", "cti-agent-x;id",
		"cti-agent-../../etc", "cti-agent-x\n--host",
	} {
		if fleetUnit.MatchString(bad) {
			t.Errorf("%q accepted, want refused", bad)
		}
	}
}
