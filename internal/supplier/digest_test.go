package supplier

import (
	"strings"
	"testing"
	"time"
)

var day = time.Date(2026, 11, 6, 7, 0, 0, 0, time.UTC)

func named(name, verdict string, hour int) Request {
	r := sampleRequest(verdict)
	r.Form.Name = name
	r.Received = time.Date(2026, 11, 5, hour, 0, 0, 0, time.UTC)
	return r
}

func TestNoRequestsSendsNothing(t *testing.T) {
	if _, ok := Digest(nil, "Org", day, "https://example.test/board", "the CYBR board", 0); ok {
		t.Error("a day with no requests produced an email")
	}
}

func TestTheDigestPointsAtTheBoardAndCountsEachVerdict(t *testing.T) {
	reqs := []Request{named("Gravel Co", No, 9), named("Cloud Backup Inc", Yes, 10), named("Mystery LLC", Unsure, 8)}
	reqs[1].TicketKey, reqs[1].TicketURL = "CYBR-12", "https://example.test/browse/CYBR-12"
	b, ok := Digest(reqs, "Example Org", day, "https://example.test/board", "the CYBR board", 0)
	if !ok {
		t.Fatal("no digest")
	}
	if b.Subject != "Example Org Supplier requests: 3 - 1 critical, 1 unsure, 1 not critical" {
		t.Errorf("subject = %q", b.Subject)
	}
	for _, want := range []string{"3 supplier requests came in. 2 have a to-do on the CYBR board.", "Board: https://example.test/board", "CYBR-12", "Treated as critical until a person decides."} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("text lacks %q:\n%s", want, b.Text)
		}
	}
	for _, want := range []string{`href="https://example.test/board"`, `href="https://example.test/browse/CYBR-12"`, "Open the CYBR board"} {
		if !strings.Contains(b.HTML, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	// Critical first, then unsure, then not critical.
	ic, iu, in := strings.Index(b.Text, "CRITICAL - Cloud Backup"), strings.Index(b.Text, "UNSURE - Mystery"), strings.Index(b.Text, "NOT CRITICAL - Gravel")
	if ic < 0 || ic >= iu || iu >= in {
		t.Errorf("not ordered critical, unsure, not critical:\n%s", b.Text)
	}
}

func TestADayOfOnlyNosSaysNoToDoAndLinksNoBoard(t *testing.T) {
	b, _ := Digest([]Request{named("Gravel Co", No, 9)}, "", day, "https://example.test/board", "", 0)
	if !strings.Contains(b.Text, "none needs a to-do") || strings.Contains(b.Text, "Board:") || strings.Contains(b.HTML, "/board") {
		t.Errorf("text:\n%s", b.Text)
	}
	if !strings.HasPrefix(b.Subject, "Supplier requests: 1 - 0 critical") {
		t.Errorf("subject = %q", b.Subject)
	}
}

func TestOnlyHTTPSLinksBecomeLinks(t *testing.T) {
	r := named("Co", Yes, 9)
	r.TicketKey, r.TicketURL = "CYBR-1", "javascript:alert(1)"
	b, _ := Digest([]Request{r}, "", day, "http://insecure.example/board", "", 0)
	if strings.Contains(b.HTML, "javascript:") || strings.Contains(b.HTML, "insecure.example") || strings.Contains(b.Text, "insecure.example") {
		t.Errorf("an unsafe link got through:\n%s", b.HTML)
	}
	if !strings.Contains(b.HTML, "CYBR-1") {
		t.Error("the ticket key was dropped with the bad link")
	}
}

func TestHostileTextIsEscapedInTheHTML(t *testing.T) {
	r := named(`<script>alert(1)</script> & Co`, Yes, 9)
	r.Decision.Reason = `<img src=x onerror=alert(1)>`
	r.From = `"><b>x</b>@example.test`
	b, _ := Digest([]Request{r}, `<Org>`, day, "", "", 0)
	for _, bad := range []string{"<script>", "<img src=x", "<b>x</b>", "<Org>"} {
		if strings.Contains(b.HTML, bad) {
			t.Errorf("%q reached the HTML unescaped", bad)
		}
	}
}

func TestTheDigestSaysHowManyAutomaticMessagesWereLeftOut(t *testing.T) {
	b, ok := Digest([]Request{named("Gravel Co", No, 9)}, "", day, "", "", 2)
	if !ok || !strings.Contains(b.Text, "2 automatic messages from the mail filter left out: not requests.") ||
		!strings.Contains(b.HTML, "2 automatic messages") {
		t.Errorf("text:\n%s", b.Text)
	}
	one, _ := Digest([]Request{named("Gravel Co", No, 9)}, "", day, "", "", 1)
	if !strings.Contains(one.Text, "1 automatic message from the mail filter left out: not a request.") {
		t.Errorf("text:\n%s", one.Text)
	}
	none, _ := Digest([]Request{named("Gravel Co", No, 9)}, "", day, "", "", 0)
	if strings.Contains(none.Text, "automatic") {
		t.Error("a line about automatic messages appeared when there were none")
	}
	// Automatic messages alone make no digest.
	if _, ok := Digest(nil, "", day, "", "", 3); ok {
		t.Error("a day of only automatic messages sent a digest")
	}
}
