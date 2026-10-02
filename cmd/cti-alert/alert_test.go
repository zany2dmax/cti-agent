package main

import (
	"strings"
	"testing"
)

// escalation is what the orchestrator sends: a healthy unit, a real message.
func escalation() failure {
	return failure{
		Kind: "ESCALATION", Unit: "cti-agent-checkin.service", Host: "crscvmtest01",
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
