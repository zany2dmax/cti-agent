package supplier

import (
	"strings"
	"testing"
	"time"
)

func sampleRequest(verdict string) Request {
	return Request{
		MessageID: "m1", ConversationID: "conv-1", Subject: "New supplier request", From: "a@example.test",
		Received: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC), State: StateRead,
		Form: &Form{Request: "New Supplier", Branch: "Plumbing", Class: "Expense", Name: "Example Gravel Co",
			MonthlySpend: "1500", RequestedBy: "A. Requester", ApprovedBy: "A. Approver", Notes: "Concrete delivery",
			Address: "1 Example Way", ARContact: "(800) 555-0100", RemitEmail: "remit@example.test"},
		Decision: Decision{Verdict: verdict, Reason: "supplies materials", Evidence: []string{"Notes: Concrete delivery"}},
	}
}

func TestOnlyCriticalAndUnsureGetAnItemUnlessAskedForNo(t *testing.T) {
	for v, want := range map[string]bool{Yes: true, Unsure: true, No: false} {
		if got := sampleRequest(v).NeedsTicket(false); got != want {
			t.Errorf("%s: NeedsTicket = %v, want %v", v, got, want)
		}
	}
	if !sampleRequest(No).NeedsTicket(true) {
		t.Error("includeNo did not give a No an item")
	}
}

func TestTheLabelIsStablePerConversationNotPerMessage(t *testing.T) {
	a, b := sampleRequest(Yes), sampleRequest(Yes)
	b.MessageID = "m2" // a reply in the same thread
	if a.Label() != b.Label() {
		t.Error("two messages of one conversation got different labels, so a rerun would file twice")
	}
	c := sampleRequest(Yes)
	c.ConversationID = "conv-2"
	if a.Label() == c.Label() || !strings.HasPrefix(a.Label(), "fleet-supplier-") || strings.ContainsAny(a.Label(), " \t") {
		t.Errorf("label %q vs %q", a.Label(), c.Label())
	}
	noConv := sampleRequest(Yes)
	noConv.ConversationID = ""
	if noConv.Label() == "" {
		t.Error("a message with no conversation id has no label")
	}
	if got := FindJQL("CYBR", a); got != `project = "CYBR" AND labels = "`+a.Label()+`"` {
		t.Errorf("jql = %s", got)
	}
}

func TestSummaryNamesTheVerdictAndTheSupplier(t *testing.T) {
	if got := TicketSummary(sampleRequest(Unsure)); got != "Supplier request - unsure: Example Gravel Co" {
		t.Errorf("summary = %q", got)
	}
	r := sampleRequest(Yes)
	r.Form = nil
	r.State = StateNone
	r.Subject = strings.Repeat("long ", 80)
	if got := TicketSummary(r); len([]rune(got)) > 140 || strings.Contains(got, "\n") {
		t.Errorf("summary not bounded to one short line: %d %q", len(got), got)
	}
}

func TestAnUnsureItemSaysSoInTheOperatorsWords(t *testing.T) {
	r := sampleRequest(Unsure)
	d := TicketDescription(r, Config{}, "CYBR")
	if !strings.Contains(d, "We could not determine a 100% Yes, so this is Unsure, and an Unsure gets a to-do on the CYBR Kanban board.") {
		t.Errorf("the Unsure wording is missing:\n%s", d)
	}
	if !strings.Contains(d, "treated as critical") {
		t.Errorf("the item does not say an Unsure is treated as critical:\n%s", d)
	}
	custom := TicketDescription(r, Config{UnsureText: "Not a sure Yes, so check it by hand."}, "CYBR")
	if !strings.Contains(custom, "Not a sure Yes, so check it by hand.") || strings.Contains(custom, "100%") {
		t.Errorf("the operator's wording was not used:\n%s", custom)
	}
}

func TestADescriptionCarriesTheBusinessFieldsAndNoBankOrContactDetail(t *testing.T) {
	d := TicketDescription(sampleRequest(Yes), Config{TPRM: "TPRM process"}, "")
	for _, want := range []string{"Example Gravel Co", "Plumbing", "Expense", "1500", "A. Requester", "Concrete delivery", "TPRM process", "supplies materials"} {
		if !strings.Contains(d, want) {
			t.Errorf("missing %q:\n%s", want, d)
		}
	}
	for _, leak := range []string{"1 Example Way", "555-0100", "remit@example.test"} {
		if strings.Contains(d, leak) {
			t.Errorf("the item carries %q, which is address, contact or remittance detail", leak)
		}
	}
}

func TestHostileTextCannotBreakTheJiraTableOrEmbedAnything(t *testing.T) {
	r := sampleRequest(Yes)
	r.Form.Name = "Evil|Co\n||x||{code}[http://evil.example|click]!http://evil.example/p.png!"
	r.Decision.Reason = "ok {panel}"
	r.Skipped = []Skipped{{Name: "w9{noformat}.pdf", Reason: "type not read"}}
	d := TicketDescription(r, Config{}, "")
	for _, bad := range []string{"{code}", "{panel}", "{noformat}", "[http", "!http"} {
		if strings.Contains(strings.ReplaceAll(d, "\\"+bad[:1], "@@"), bad) {
			t.Errorf("%q survived unescaped:\n%s", bad, d)
		}
	}
	for _, line := range strings.Split(d, "\n") {
		if strings.HasPrefix(line, "|Supplier|") && strings.Count(line, "|") != 3+strings.Count(line, `\|`) {
			t.Errorf("a pipe in the name broke the row: %q", line)
		}
	}
}

func TestEachFormStateSaysWhatHappened(t *testing.T) {
	for st, want := range map[FormState]string{
		StateLinked: "arrived as a link", StateUnreadable: "not a supplier form", StateNone: "judged from the message text",
	} {
		r := sampleRequest(Unsure)
		r.State, r.Form = st, nil
		if d := TicketDescription(r, Config{}, ""); !strings.Contains(d, want) {
			t.Errorf("%s: missing %q:\n%s", st, want, d)
		}
	}
}

func TestSkippedFilesAndDowngradeNotesAreShown(t *testing.T) {
	r := sampleRequest(Unsure)
	r.Skipped = []Skipped{{Name: "W-9.pdf", Reason: "type not read"}}
	r.Decision.Notes = []string{"form not readable: linked, not attached"}
	d := TicketDescription(r, Config{}, "")
	for _, want := range []string{"W-9.pdf", "never opens the tax and bank forms", "linked, not attached", "What to be careful about"} {
		if !strings.Contains(d, want) {
			t.Errorf("missing %q:\n%s", want, d)
		}
	}
}
