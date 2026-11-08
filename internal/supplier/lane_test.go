package supplier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

type fakeMail struct{ msgs []graph.AddressedMessage }

func (f fakeMail) Addressed(context.Context, time.Time) ([]graph.AddressedMessage, error) {
	return f.msgs, nil
}

func msg(id, conv, subject, from, body string, hour int, attach bool) graph.AddressedMessage {
	return graph.AddressedMessage{ID: id, ConversationID: conv, Subject: subject, From: from, BodyText: body,
		Received: time.Date(2026, 11, 5, hour, 0, 0, 0, time.UTC), HasAttachments: attach}
}

// perMessage lets one fakeSource serve different attachments per message.
type perMessage struct {
	atts    map[string][]Attachment
	content map[string][]byte
	opened  []string
}

func (p *perMessage) Attachments(_ context.Context, id string) ([]Attachment, error) {
	return p.atts[id], nil
}
func (p *perMessage) Content(_ context.Context, _, id string, _ int64) ([]byte, error) {
	p.opened = append(p.opened, id)
	return p.content[id], nil
}

const mailbox = "box@example.test"

// epoch is before every message the tests make, so the window includes them all.
var epoch = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func TestOneConversationIsOneRequestAndTheFormMessageCarriesIt(t *testing.T) {
	form := workbook(t, completeForm)
	src := &perMessage{
		atts:    map[string][]Attachment{"m1": {file("f", "Supplier Form.xlsx", 4000), file("w", "W-9.pdf", 4000)}},
		content: map[string][]byte{"f": form},
	}
	mail := fakeMail{[]graph.AddressedMessage{
		msg("m2", "c1", "Re: new supplier", "approver@example.test", "Approved", 12, false),
		msg("m1", "c1", "new supplier", "requester@example.test", "Please set up Example Geo.", 9, true),
	}}
	items, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, epoch)
	if err != nil || len(items) != 1 {
		t.Fatalf("items %d, err %v", len(items), err)
	}
	r := items[0].Request
	if r.State != StateRead || r.MessageID != "m1" || r.Name() != "Example Geo Services, Inc." {
		t.Errorf("request = %+v", r)
	}
	if len(src.opened) != 1 || src.opened[0] != "f" {
		t.Errorf("opened %v, want only the form", src.opened)
	}
	if !strings.Contains(items[0].Input, "REPLY from approver@example.test: Approved") {
		t.Errorf("the reply was not shown to the model:\n%s", items[0].Input)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Name != "W-9.pdf" {
		t.Errorf("skipped = %+v", r.Skipped)
	}
}

func TestAFormSharedAsALinkIsLinkedNotNone(t *testing.T) {
	mail := fakeMail{[]graph.AddressedMessage{
		msg("m1", "c1", "Fw: onboarding", "a@example.test", "Supplier_Request__Example.xlsx\n\nMichael needs to approve.", 9, true),
		msg("m2", "c2", "another", "b@example.test", "see https://example-my.sharepoint.com/:x:/p/someone/abc", 10, false),
		msg("m3", "c3", "plain", "c@example.test", "We would like to add a gravel supplier.", 11, false),
	}}
	src := &perMessage{atts: map[string][]Attachment{
		"m1": {file("w", "W-9_Example.pdf", 5000), file("b", "Banking Info.pdf", 5000)},
	}}
	items, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, epoch)
	if err != nil || len(items) != 3 {
		t.Fatalf("items %d, err %v", len(items), err)
	}
	got := map[string]FormState{}
	for _, it := range items {
		got[it.Request.MessageID] = it.Request.State
	}
	if got["m1"] != StateLinked || got["m2"] != StateLinked || got["m3"] != StateNone {
		t.Errorf("states = %v", got)
	}
	if len(src.opened) != 0 {
		t.Errorf("opened %v: nothing readable was attached", src.opened)
	}
}

func TestAnAttachedSpreadsheetThatIsNotTheFormIsUnreadable(t *testing.T) {
	src := &perMessage{
		atts:    map[string][]Attachment{"m1": {file("x", "budget.xlsx", 1000)}},
		content: map[string][]byte{"x": []byte("not a workbook")},
	}
	mail := fakeMail{[]graph.AddressedMessage{msg("m1", "c1", "supplier", "a@example.test", "form attached", 9, true)}}
	items, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, epoch)
	if err != nil || len(items) != 1 || items[0].Request.State != StateUnreadable {
		t.Fatalf("%+v %v", items, err)
	}
}

func TestSeenRequestsAndTheFleetsOwnMailAreNotCollected(t *testing.T) {
	mail := fakeMail{[]graph.AddressedMessage{
		msg("m1", "c1", "old one", "a@example.test", "gravel", 9, false),
		msg("m2", "c2", "new one", "b@example.test", "paving", 10, false),
		msg("m3", "c3", "our report", mailbox, "digest", 11, false),
	}}
	old := Request{ConversationID: "c1"}
	seen := map[string]bool{old.Label(): true}
	items, err := Collect(context.Background(), mail, &perMessage{}, Policy{}, Config{}, seen, mailbox, epoch)
	if err != nil || len(items) != 1 || items[0].Request.MessageID != "m2" {
		t.Fatalf("%+v %v", items, err)
	}
}

type fakeTickets struct {
	existing map[string]string // label substring -> key
	created  []string
	failOn   string
}

func (f *fakeTickets) Find(_ context.Context, jql string) (string, string, bool, error) {
	for label, key := range f.existing {
		if strings.Contains(jql, label) {
			return key, "https://example.test/browse/" + key, true, nil
		}
	}
	return "", "", false, nil
}

func (f *fakeTickets) Create(_ context.Context, summary, _ string, labels []string) (string, string, error) {
	if f.failOn != "" && strings.Contains(summary, f.failOn) {
		return "", "", errors.New("jira said no")
	}
	key := fmt.Sprintf("CYBR-%d", 100+len(f.created))
	f.created = append(f.created, summary)
	return key, "https://example.test/browse/" + key, nil
}

func itemFor(id, name string) Item {
	r := sampleRequest(No)
	r.MessageID, r.ConversationID = id, "conv-"+id
	r.Form.Name = name
	in := Input{MessageID: id, Sender: r.From, Subject: r.Subject, State: StateRead, Form: r.Form, Body: "x"}
	return Item{Request: r, Input: Render(in, Config{}), Source: in.Source()}
}

func yes(id string) []byte {
	return []byte(fmt.Sprintf(`{"schema":"cti-supplier/1","message_id":%q,"verdict":"yes","reason":"software","evidence":["SUBJECT: New supplier request"]}`, id))
}

func TestFinishFilesYesAndUnsureOnceAndNotNo(t *testing.T) {
	items := []Item{itemFor("a", "Cloud Backup Inc"), itemFor("b", "Mystery LLC"), itemFor("c", "Gravel Co")}
	no := []byte(`{"schema":"cti-supplier/1","message_id":"c","verdict":"no","reason":"gravel","evidence":["SUBJECT: New supplier request"]}`)
	results := map[int][]byte{0: yes("a"), 2: no} // 1 has no judgement at all
	tk := &fakeTickets{}
	out := Finish(context.Background(), items, results, Config{}, tk, "CYBR", true)
	if len(tk.created) != 2 {
		t.Fatalf("created %v, want the yes and the unsure", tk.created)
	}
	if out[0].Request.Decision.Verdict != Yes || out[1].Request.Decision.Verdict != Unsure || out[2].Request.Decision.Verdict != No {
		t.Errorf("verdicts = %s %s %s", out[0].Request.Decision.Verdict, out[1].Request.Decision.Verdict, out[2].Request.Decision.Verdict)
	}
	if out[0].Request.TicketKey == "" || out[1].Request.TicketKey == "" || out[2].Ticket != "" {
		t.Errorf("tickets = %q %q %q", out[0].Ticket, out[1].Ticket, out[2].Ticket)
	}
	if !strings.Contains(out[1].Request.Decision.Reason, "No judgement") {
		t.Errorf("a missing judgement should say so: %q", out[1].Request.Decision.Reason)
	}
}

func TestFinishFindsAnExistingItemInsteadOfFilingAnother(t *testing.T) {
	it := itemFor("a", "Cloud Backup Inc")
	tk := &fakeTickets{existing: map[string]string{it.Request.Label(): "CYBR-7"}}
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, tk, "CYBR", true)
	if len(tk.created) != 0 || out[0].Ticket != "found" || out[0].Request.TicketKey != "CYBR-7" {
		t.Errorf("%+v created %v", out[0], tk.created)
	}
}

func TestADryRunOrNoProjectWritesNothing(t *testing.T) {
	it := itemFor("a", "Cloud Backup Inc")
	tk := &fakeTickets{}
	if out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, tk, "CYBR", false); out[0].Ticket != "would-create" || len(tk.created) != 0 {
		t.Errorf("dry run: %+v", out[0])
	}
	if out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, tk, "", true); out[0].Ticket != "error" || len(tk.created) != 0 {
		t.Errorf("no project: %+v", out[0])
	}
	if out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, nil, "CYBR", true); out[0].Ticket != "error" {
		t.Errorf("no jira: %+v", out[0])
	}
}

func TestOneItemFailingDoesNotStopTheOthers(t *testing.T) {
	items := []Item{itemFor("a", "Cloud Backup Inc"), itemFor("b", "Network Gear Co")}
	tk := &fakeTickets{failOn: "Cloud Backup"}
	out := Finish(context.Background(), items, map[int][]byte{0: yes("a"), 1: yes("b")}, Config{}, tk, "CYBR", true)
	if out[0].Ticket != "error" || out[0].Err == "" || out[1].Ticket != "created" {
		t.Errorf("%+v / %+v", out[0], out[1])
	}
}

func TestEvidenceIsCheckedAgainstWhatTheModelWasShown(t *testing.T) {
	it := itemFor("a", "Cloud Backup Inc")
	bad := []byte(`{"schema":"cti-supplier/1","message_id":"a","verdict":"yes","reason":"software","evidence":["a line that was never in the request"]}`)
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: bad}, Config{}, nil, "", false)
	if out[0].Request.Decision.Verdict != Unsure {
		t.Errorf("a yes with an invented quote stood: %+v", out[0].Request.Decision)
	}
}

func TestSeenRoundTripsAndForgetsOldEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	s, err := LoadSeen(path)
	if err != nil || len(s) != 0 {
		t.Fatalf("%v %v", s, err)
	}
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	s.Record([]string{"fleet-supplier-a"}, now.Add(-100*24*time.Hour))
	s.Record([]string{"fleet-supplier-b"}, now)
	if s.Has("fleet-supplier-a") || !s.Has("fleet-supplier-b") {
		t.Errorf("old entry not forgotten: %v", s)
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	back, err := LoadSeen(path)
	if err != nil || !back.Has("fleet-supplier-b") {
		t.Errorf("%v %v", back, err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSeen(path); err == nil {
		t.Error("a damaged record was accepted")
	}
}

func TestAThreadWithANewReplyIsJudgedWithItsOlderFormMessage(t *testing.T) {
	form := workbook(t, completeForm)
	src := &perMessage{
		atts:    map[string][]Attachment{"old": {file("f", "Supplier Form.xlsx", 4000)}},
		content: map[string][]byte{"f": form},
	}
	day := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, time.UTC) }
	mk := func(id, conv, subj string, at time.Time, attach bool) graph.AddressedMessage {
		m := msg(id, conv, subj, "a@example.test", "text", 0, attach)
		m.Received = at
		return m
	}
	mail := fakeMail{[]graph.AddressedMessage{
		mk("old", "c1", "new supplier", day(5, 21), true), // before the window
		mk("new", "c1", "Re: new supplier", day(6, 12), false),
		mk("stale", "c2", "an old thread", day(1, 9), false), // wholly before the window
	}}
	items, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, day(5, 22))
	if err != nil || len(items) != 1 {
		t.Fatalf("items %d, err %v", len(items), err)
	}
	r := items[0].Request
	if r.State != StateRead || r.MessageID != "old" {
		t.Errorf("the thread was judged without its form: state %s, message %s", r.State, r.MessageID)
	}
}

func TestTheMailboxIsReadBackFurtherThanTheWindow(t *testing.T) {
	var asked time.Time
	m := askedMail{&asked}
	since := time.Date(2026, 11, 5, 22, 0, 0, 0, time.UTC)
	if _, err := Collect(context.Background(), m, &perMessage{}, Policy{}, Config{}, nil, mailbox, since); err != nil {
		t.Fatal(err)
	}
	if want := since.Add(-contextLookback); !asked.Equal(want) {
		t.Errorf("read from %v, want %v", asked, want)
	}
}

type askedMail struct{ at *time.Time }

func (a askedMail) Addressed(_ context.Context, since time.Time) ([]graph.AddressedMessage, error) {
	*a.at = since
	return nil, nil
}
