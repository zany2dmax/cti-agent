package vmscan

import (
	"strings"
	"testing"
	"time"
)

func TestTicketLineSaysWhatHappened(t *testing.T) {
	url := "https://example.atlassian.net/browse/HD-12"
	for action, want := range map[string]string{
		"created":          "filed HD-12",
		"commented":        "the list changed",
		"unchanged":        "already has this exact list",
		"resolved":         "every row is corrected",
		"resolved-earlier": "in an earlier week",
		"would-comment":    "(preview): would add",
		"gate-closed":      "NOT updated",
	} {
		line, u := TicketLine(&TicketRef{Action: action, Key: "HD-12", URL: url, Status: "Open"})
		if !strings.Contains(line, want) || u != url {
			t.Errorf("%s: line %q url %q", action, line, u)
		}
	}
	if line, _ := TicketLine(&TicketRef{Action: "none"}); line != "" {
		t.Errorf("none: %q", line)
	}
	if line, _ := TicketLine(nil); !strings.Contains(line, "unavailable") {
		t.Errorf("nil: %q", line)
	}
}

// Only a well-formed https browse link for the ref's own key reaches the email.
func TestTicketLineDropsABadLink(t *testing.T) {
	for _, u := range []string{"http://example.atlassian.net/browse/HD-12",
		"https://example.atlassian.net/browse/HD-13", "javascript:alert(1)"} {
		if _, got := TicketLine(&TicketRef{Action: "unchanged", Key: "HD-12", URL: u}); got != "" {
			t.Errorf("%q reached the email", u)
		}
	}
}

func sheetWeek(slot bool) Week {
	return Week{Coverage: &Coverage{Checked: 1, TicketSlot: slot}}
}

// The renderer leaves exactly one slot in each form when asked, none
// otherwise, and the stamp fills it with the ticket and its link.
func TestTheReportHasOneSlotAndTheStampFillsIt(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	b := Render(sheetWeek(true), "Org", now)
	if strings.Count(b.HTML, TicketSlot) != 1 || strings.Count(b.Text, TicketSlot) != 1 {
		t.Fatalf("slots: html %d text %d", strings.Count(b.HTML, TicketSlot), strings.Count(b.Text, TicketSlot))
	}
	if strings.Contains(b.HTML, slotSentinel) || strings.Contains(b.Text, slotSentinel) {
		t.Fatal("the sentinel reached the report")
	}
	none := Render(sheetWeek(false), "Org", now)
	if strings.Contains(none.HTML, TicketSlot) || strings.Contains(none.Text, TicketSlot) {
		t.Fatal("a slot without --ticket-slot")
	}

	r := &TicketRef{Action: "commented", Key: "HD-12", URL: "https://example.atlassian.net/browse/HD-12"}
	h := StampTicket(b.HTML, true, r)
	if strings.Contains(h, TicketSlot) || !strings.Contains(h, `href="https://example.atlassian.net/browse/HD-12"`) {
		t.Errorf("html stamp: %q", h)
	}
	txt := StampTicket(b.Text, false, r)
	if strings.Contains(txt, TicketSlot) || !strings.Contains(txt, "HD-12") ||
		!strings.Contains(txt, "https://example.atlassian.net/browse/HD-12") {
		t.Errorf("text stamp missing the ticket")
	}
	if got := StampTicket(b.Text, false, &TicketRef{Action: "none"}); strings.Contains(got, TicketSlot) {
		t.Error("a 'none' stamp left the slot")
	}
}

// A location name in the spreadsheet carrying the marker text cannot add a
// second slot: only the renderer's own one survives.
func TestASlotInTheSpreadsheetIsRemoved(t *testing.T) {
	w := sheetWeek(true)
	w.Coverage.Unavailable = "the sheet says " + TicketSlot + " here and <!--CTI_VMSCAN_" + TicketSlot + "TICKET--> there"
	b := Render(w, "Org", time.Now())
	if strings.Count(b.Text, TicketSlot) != 1 || strings.Count(b.HTML, TicketSlot) != 1 {
		t.Errorf("slots: html %d text %d", strings.Count(b.HTML, TicketSlot), strings.Count(b.Text, TicketSlot))
	}
}
