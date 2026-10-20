package domains

import (
	"strings"
	"testing"
)

func TestTheTicketIsStampedIntoBothForms(t *testing.T) {
	r := &TicketRef{Action: "commented", Key: "SEC-50", Status: "Waiting for support",
		URL: "https://jira.example.com/browse/SEC-50"}
	for _, isHTML := range []bool{true, false} {
		got := StampTicket("before\n"+TicketSlot+"\nafter", isHTML, r)
		if strings.Contains(got, TicketSlot) {
			t.Errorf("html=%v: slot left behind", isHTML)
		}
		if !strings.Contains(got, "SEC-50 (Waiting for support)") ||
			!strings.Contains(got, "https://jira.example.com/browse/SEC-50") {
			t.Errorf("html=%v: %s", isHTML, got)
		}
	}
}

func TestAnUnusableURLIsNotPutInTheEmail(t *testing.T) {
	for _, u := range []string{
		"http://jira.example.com/browse/SEC-50",        // not https
		"https://evil.example.com/login?next=SEC-50",   // not a browse link
		"https://jira.example.com/browse/SEC-51",       // another ticket
		"javascript:alert(1)//https://x/browse/SEC-50", // not a URL at all
	} {
		if _, url := TicketLine(&TicketRef{Action: "created", Key: "SEC-50", URL: u}); url != "" {
			t.Errorf("%q made it into the email", u)
		}
	}
	if _, url := TicketLine(&TicketRef{Action: "created", Key: "<b>SEC-50</b>",
		URL: "https://jira.example.com/browse/SEC-50"}); url != "" {
		t.Error("a malformed key still produced a link")
	}
}

func TestNothingToSayRemovesTheSlotAndNoRefSaysUnavailable(t *testing.T) {
	if got := StampTicket("a"+TicketSlot+"b", false, &TicketRef{Action: "none"}); got != "ab" {
		t.Errorf("none: %q", got)
	}
	if got := StampTicket(TicketSlot, false, nil); !strings.Contains(got, "unavailable") {
		t.Errorf("no ref: %q", got)
	}
	if got := StampTicket(TicketSlot, true, &TicketRef{Action: "error", Key: "SEC-50",
		Note: "the comment was refused <script>"}); strings.Contains(got, "<script>") ||
		!strings.Contains(got, "NOT updated") {
		t.Errorf("error line not escaped or not said: %q", got)
	}
}

func TestTheReportOnlyCarriesASlotWhenAsked(t *testing.T) {
	r := Report{Registrar: "GoDaddy"}
	if strings.Contains(r.Render().HTML, TicketSlot) {
		t.Error("an unstamped slot in a report nobody will stamp")
	}
	r.TicketSlot = true
	b := r.Render()
	if !strings.Contains(b.HTML, TicketSlot) || !strings.Contains(b.Text, TicketSlot) {
		t.Error("asked for a slot, got none")
	}
}

func TestAMarkerInObservedDataIsNotAStampSite(t *testing.T) {
	r := Report{Registrar: "GoDaddy", TicketSlot: true,
		Findings: []Finding{{Domain: "a.example.com", Sev: Medium, Area: "web",
			Text: "page title " + TicketSlot}}}
	b := r.Render()
	for name, body := range map[string]string{"text": b.Text, "html": b.HTML} {
		if n := strings.Count(body, TicketSlot); n != 1 {
			t.Errorf("%s: %d slots, want exactly the one the renderer placed", name, n)
		}
	}
}

func TestJiraFieldsCannotBreakTheLine(t *testing.T) {
	line, _ := TicketLine(&TicketRef{Action: "commented", Key: "SEC-50", Status: "Open\nInjected: yes"})
	if strings.Contains(line, "\n") {
		t.Errorf("a newline in the status reached the report: %q", line)
	}
	if line, _ := TicketLine(&TicketRef{Action: "created", Key: "bad key"}); strings.Contains(line, "filed  for") {
		t.Errorf("empty key left a gap: %q", line)
	}
}
