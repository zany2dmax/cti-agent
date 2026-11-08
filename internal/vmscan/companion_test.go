package vmscan

import (
	"fmt"
	"testing"
	"time"
)

// Companion bodies mirror the real notices' structure: a hidden preheader, a
// <pre> label block, and (Scan Completed only) the wrapped report link. The
// titles and references are invented.

func completedBody(title, start, ref string) string {
	return fmt.Sprintf(`<div style="display:none">Email scan summary by Qualys Scan Title : decoy Start Date : 01/01/2020 at 01:00:00 AM</div>
<pre>--------------------------------------------------------------------------
   Email scan summary by Qualys
   Scan Title       : %s
   Start Date       : %s
   Scan Status      : Finished
Click here to view your full scan report: <a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/fo/report/report_view.php?ref=scan*%s&amp;authfirst=true&amp;em=1__;Lw!!A!B$">link</a>
</pre>`, title, start, ref)
}

func taskDoneBody(title, launch string) string {
	return fmt.Sprintf(`<pre>Custom text:
A Qualys scan is finished.
 Company               : Example Co
 Type                  : Vulnerability Scan
 Title                 : %s
 Launch Time           : %s
 Duration              : 1 day 00:02:33
</pre>`, title, launch)
}

func TestRecognisesOnlyQualysCompanionNotices(t *testing.T) {
	var p Provider
	for _, c := range []struct {
		from, subject string
		want          bool
	}{
		{"qualys@qualys.net", "Qualys: Scan Completed", true},
		{"qualys@qualys.net", "Qualys: Completed Vulnerability Scan Notification", true},
		{"Qualys <noreply@qualys.com>", "Qualys: Scan Completed", true},
		// The team mailbox as sender: a schedule whose From Address is the
		// owner. Never claimed - a lookalike must not be deleted.
		{"team@example.com", "Qualys: Scan Completed", false},
		{"qualys@qualys.net.attacker.example", "Qualys: Scan Completed", false},
		// A person passing one on needs a person.
		{"qualys@qualys.net", "FW: Qualys: Scan Completed", false},
		// The results notice is not a companion.
		{"qualys@qualys.net", "Qualys: Scan Results", false},
	} {
		if got := p.RecognisesCompanion(c.from, c.subject); got != c.want {
			t.Errorf("%s / %q: %v, want %v", c.from, c.subject, got, c.want)
		}
	}
}

func TestACompanionMatchesItsRunAndNoOther(t *testing.T) {
	var p Provider
	run := Scan{Title: "Example Weekly", Ref: "scan/1700000000.11111",
		Start: time.Date(2026, 11, 5, 13, 0, 22, 0, time.UTC)}
	const start = "11/05/2026 at 01:00:22 PM (GMT+0000)"

	c := p.ParseCompanion(completedBody("Example Weekly", start, "1700000000.11111"))
	if c.Title != "Example Weekly" || c.Ref != "scan/1700000000.11111" || !c.Start.Equal(run.Start) {
		t.Fatalf("parsed %+v - the hidden preheader must not be read", c)
	}
	if !c.Matches(run) {
		t.Error("Scan Completed for the same run must match")
	}
	// The reference decides when both carry one: same title and time, but
	// another run.
	if p.ParseCompanion(completedBody("Example Weekly", start, "1700000099.22222")).Matches(run) {
		t.Error("a different report reference is a different run")
	}

	if !p.ParseCompanion(taskDoneBody("Example Weekly", start)).Matches(run) {
		t.Error("the task-owner notice for the same title and launch time must match")
	}
	for name, body := range map[string]string{
		"a minute later":  taskDoneBody("Example Weekly", "11/05/2026 at 01:01:22 PM (GMT+0000)"),
		"another title":   taskDoneBody("Other Weekly", start),
		"no launch time":  taskDoneBody("Example Weekly", "unknown"),
		"no title at all": taskDoneBody("", start),
	} {
		if p.ParseCompanion(body).Matches(run) {
			t.Errorf("%s: matched, and would be deleted", name)
		}
	}
}
