package qualys

import (
	"testing"
	"time"
)

// Mirrors the real "scheduled to start" notice: hidden preheader, Proofpoint
// banner, and the task block in <p> with <br /> line breaks. Names invented.
const scheduledNotice = `<div style="display:none !important;display:none">Custom Text: Title: Decoy Next Launch: 01/01/2020 at 00:00:00</div>
<div id="pfptBannerabc123" style="display:block">This Message Is From an External Sender</div>
<div><p>Custom Text: <br />Example Shop WAS scan starts soon </p><p>The following task is scheduled to start on 11/08/2026 at 01:27:00 (GMT +0000)<br />---- </p>
<p>Scheduled Task Information:<br /><br />Company: Qualys<br />Task Owner: Someone(acct)<br />Type: Web Application Vulnerability Scan<br />Title: Example Shop<br />Next Launch: 11/08/2026 at 01:27:00 (GMT +0000)<br />Previous Duration: 12:22:28<br /></p></div>`

func TestParsesTheScheduledNotice(t *testing.T) {
	title, launch := Provider{}.ParseScheduled(scheduledNotice)
	if title != "Example Shop" {
		t.Errorf("title = %q - the hidden preheader must not be read", title)
	}
	if want := time.Date(2026, 11, 8, 1, 27, 0, 0, time.UTC); !launch.Equal(want) {
		t.Errorf("launch = %v, want %v", launch, want)
	}
}

func TestRecognisesOnlyQualysScheduledNotices(t *testing.T) {
	const subj = "Qualys: Scheduled Web Application Vulnerability Scan Notification"
	var p Provider
	for _, c := range []struct {
		from, subject string
		want          bool
	}{
		{"qualys@qualys.net", subj, true},
		{"team@example.com", subj, false},
		{"Qualys <qualys@qualys.net.attacker.example>", subj, false},
		{"qualys@qualys.net", "RE: " + subj, false},
		{"qualys@qualys.net", "Qualys: Web Application Vulnerability Scan Results - Example Shop Run #41", false},
	} {
		if got := p.RecognisesScheduled(c.from, c.subject); got != c.want {
			t.Errorf("%s / %q: %v, want %v", c.from, c.subject, got, c.want)
		}
	}
}
