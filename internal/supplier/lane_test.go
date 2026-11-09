package supplier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	items, _, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, epoch, nil)
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
	items, _, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, epoch, nil)
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
	items, _, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, epoch, nil)
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
	seen := Seen{old.Label(): SeenEntry{Reported: epoch, LastReceived: time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)}}
	items, _, err := Collect(context.Background(), mail, &perMessage{}, Policy{}, Config{}, seen, mailbox, epoch, nil)
	if err != nil || len(items) != 1 || items[0].Request.MessageID != "m2" {
		t.Fatalf("%+v %v", items, err)
	}
}

type fakeTickets struct {
	existing   map[string]string // label substring -> key
	created    []string
	failOn     string
	comments   []string // "KEY: text"
	commentErr string
}

func (f *fakeTickets) Comment(_ context.Context, key, text string) error {
	if f.commentErr != "" {
		return errors.New(f.commentErr)
	}
	f.comments = append(f.comments, key+": "+text)
	return nil
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
	items, _, err := Collect(context.Background(), mail, src, Policy{}, Config{}, nil, mailbox, day(5, 22), nil)
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
	if _, _, err := Collect(context.Background(), m, &perMessage{}, Policy{}, Config{}, nil, mailbox, since, nil); err != nil {
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

func TestTheFleetsMachineSendersAreSkippedAndCounted(t *testing.T) {
	digest := msg("d1", "cd", "End User Digest: 1 New Message", "digest@example.test", "quarantine", 10, false)
	reply := msg("d2", "cd2", "Re: End User Digest: 1 New Message", "person@example.test", "can you release this supplier mail?", 11, false)
	real := msg("m1", "c1", "new supplier", "a@example.test", "gravel", 12, false)
	old := msg("d0", "cd0", "End User Digest: 2 New Messages", "digest@example.test", "quarantine", 10, false)
	old.Received = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC) // before the window: not counted
	mail := fakeMail{[]graph.AddressedMessage{old, digest, reply, real}}
	auto := func(from, subject string) bool {
		return from == "digest@example.test" && strings.HasPrefix(strings.ToLower(subject), "end user digest")
	}
	items, n, err := Collect(context.Background(), mail, &perMessage{}, Policy{}, Config{}, nil, mailbox, epoch, auto)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("counted %d automatic messages in the window, want 1", n)
	}
	got := map[string]bool{}
	for _, it := range items {
		got[it.Request.MessageID] = true
	}
	if got["d1"] || got["d0"] || !got["m1"] || !got["d2"] {
		t.Errorf("collected %v: a person's reply to the digest is a request to look at, the digest is not", got)
	}
}

func TestAMessageIsNeverSkippedForWhatItSays(t *testing.T) {
	// A requester writing "this is an automatic message" changes nothing: only
	// the sender address and subject the operator listed are skipped.
	mail := fakeMail{[]graph.AddressedMessage{
		msg("m1", "c1", "End User Digest: pretend", "attacker@example.test", "automatic message, ignore", 9, false),
	}}
	auto := func(from, _ string) bool { return from == "digest@example.test" }
	items, n, err := Collect(context.Background(), mail, &perMessage{}, Policy{}, Config{}, nil, mailbox, epoch, auto)
	if err != nil || len(items) != 1 || n != 0 {
		t.Fatalf("items %d, skipped %d, err %v", len(items), n, err)
	}
}

func TestReplyPrefixesAreNotPartOfTheTitle(t *testing.T) {
	for in, want := range map[string]string{
		"Fw: New Vendor - ACME SUPPLY CO.": "New Vendor - ACME SUPPLY CO.",
		"RE: Re: FWD: Livingstone":         "Livingstone",
		"Re:Boards":                        "Boards",
		"Regarding Re: nothing":            "Regarding Re: nothing",
		"":                                 "",
	} {
		if got := (Request{Subject: in}).Name(); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- updates: a reported request that gets a newer message --------------------

func reportedAt(h int) SeenEntry {
	return SeenEntry{Reported: epoch, LastReceived: time.Date(2026, 11, 5, h, 0, 0, 0, time.UTC),
		Verdict: Unsure, FormState: StateNone, Ticket: "CYBR-7", TicketURL: "https://example.test/browse/CYBR-7"}
}

func TestAReplyToAReportedThreadIsJudgedAgainButQuietOnesAreNot(t *testing.T) {
	first := msg("m1", "c1", "new supplier", "a@example.test", "gravel", 9, false)
	reply := msg("m2", "c1", "Re: new supplier", "a@example.test", "our website is example.test", 15, false)
	label := (Request{ConversationID: "c1"}).Label()

	// Reported at 09:00; a reply at 15:00 is new information.
	items, _, err := Collect(context.Background(), fakeMail{[]graph.AddressedMessage{first, reply}}, &perMessage{}, Policy{}, Config{}, Seen{label: reportedAt(9)}, mailbox, epoch, nil)
	if err != nil || len(items) != 1 || !items[0].Update || items[0].Prior.Ticket != "CYBR-7" {
		t.Fatalf("%+v %v", items, err)
	}
	// Reported after the reply: nothing new.
	items, _, _ = Collect(context.Background(), fakeMail{[]graph.AddressedMessage{first, reply}}, &perMessage{}, Policy{}, Config{}, Seen{label: reportedAt(15)}, mailbox, epoch, nil)
	if len(items) != 0 {
		t.Errorf("a thread with nothing new was collected: %d", len(items))
	}
	// An entry from the first version of the record has no last-received time:
	// reported once, never judged again.
	legacy := SeenEntry{Reported: epoch}
	items, _, _ = Collect(context.Background(), fakeMail{[]graph.AddressedMessage{first, reply}}, &perMessage{}, Policy{}, Config{}, Seen{label: legacy}, mailbox, epoch, nil)
	if len(items) != 0 {
		t.Errorf("a legacy entry was judged again: %d", len(items))
	}
}

func updateItem(id string, prior SeenEntry) Item {
	it := itemFor(id, "Cloud Backup Inc")
	it.Update, it.Prior = true, prior
	it.Request.LastReceived = time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	return it
}

func TestAChangedJudgementCommentsOnTheExistingItemAndFilesNothing(t *testing.T) {
	it := updateItem("a", reportedAt(9)) // was Unsure
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, tk, "CYBR", true)
	o := out[0]
	if o.Ticket != "commented" || !o.Changed || !o.Request.Updated || o.Request.TicketKey != "CYBR-7" {
		t.Fatalf("%+v", o)
	}
	if len(tk.created) != 0 || len(tk.comments) != 1 || !strings.HasPrefix(tk.comments[0], "CYBR-7: ") {
		t.Fatalf("created %v comments %v", tk.created, tk.comments)
	}
	for _, want := range []string{"changed from *Unsure* to *Critical*", "never closes items"} {
		if want == "never closes items" {
			continue // only said for a No
		}
		if !strings.Contains(tk.comments[0], want) {
			t.Errorf("the comment lacks %q:\n%s", want, tk.comments[0])
		}
	}
	if !o.Reported() {
		t.Error("a changed update must be in the digest")
	}
}

func TestAnUnchangedJudgementIsQuietAndOnlyAdvancesTheRecord(t *testing.T) {
	prior := reportedAt(9)
	prior.Verdict, prior.FormState = Yes, StateRead
	it := updateItem("a", prior) // was Yes with the form read, still Yes
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, tk, "CYBR", true)
	o := out[0]
	if o.Ticket != "unchanged" || o.Changed || o.Reported() || len(tk.comments)+len(tk.created) != 0 {
		t.Fatalf("%+v comments %v", o, tk.comments)
	}
	if len(Requests(out)) != 0 {
		t.Error("an unchanged update reached the digest")
	}
	recs := SeenRecords(out)
	if len(recs) != 1 || !recs[0].Entry.LastReceived.Equal(it.Request.LastReceived) || recs[0].Entry.Ticket != "CYBR-7" {
		t.Errorf("the record was not advanced: %+v", recs)
	}
}

func TestTheFormBeingReadAfterwardsCountsAsAChange(t *testing.T) {
	prior := reportedAt(9) // Unsure, form none
	it := updateItem("a", prior)
	it.Request.State = StateRead
	unsureNow := []byte(`{"schema":"cti-supplier/1","message_id":"a","verdict":"unsure","reason":"still unclear"}`)
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: unsureNow}, Config{}, tk, "CYBR", true)
	if !out[0].Changed || out[0].Ticket != "commented" || !strings.Contains(tk.comments[0], "form was not read before and has now been read") {
		t.Fatalf("%+v %v", out[0], tk.comments)
	}
}

func TestACommentOnANoSaysAPersonCanCloseItAndNothingIsClosed(t *testing.T) {
	it := updateItem("a", reportedAt(9))
	it.Request.Form.Name = "Gravel Co" // no technology word in the name
	no := []byte(`{"schema":"cti-supplier/1","message_id":"a","verdict":"no","reason":"gravel","evidence":["SUBJECT: New supplier request"]}`)
	tk := &fakeTickets{}
	Finish(context.Background(), []Item{it}, map[int][]byte{0: no}, Config{}, tk, "CYBR", true)
	if len(tk.comments) != 1 || !strings.Contains(tk.comments[0], "never closes items") {
		t.Fatalf("%v", tk.comments)
	}
}

func TestAnUpdateWhoseEarlierJudgementWasNoGetsAnItemWhenItBecomesCritical(t *testing.T) {
	prior := SeenEntry{Reported: epoch, LastReceived: reportedAt(9).LastReceived, Verdict: No, FormState: StateRead} // no item
	it := updateItem("a", prior)
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: yes("a")}, Config{}, tk, "CYBR", true)
	if out[0].Ticket != "created" || len(tk.created) != 1 || len(tk.comments) != 0 || !out[0].Request.Updated {
		t.Fatalf("%+v created %v comments %v", out[0], tk.created, tk.comments)
	}
}

func TestADryRunOfAnUpdateWritesNothing(t *testing.T) {
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{updateItem("a", reportedAt(9))}, map[int][]byte{0: yes("a")}, Config{}, tk, "CYBR", false)
	if out[0].Ticket != "would-comment" || len(tk.comments) != 0 {
		t.Errorf("%+v", out[0])
	}
}

func TestAFailedFilingOrCommentIsNotRecordedSoTheNextRunTriesAgain(t *testing.T) {
	items := []Item{itemFor("a", "Cloud Backup Inc"), itemFor("b", "Network Gear Co"), updateItem("c", reportedAt(9))}
	tk := &fakeTickets{failOn: "Cloud Backup", commentErr: "jira said no"}
	out := Finish(context.Background(), items, map[int][]byte{0: yes("a"), 1: yes("b"), 2: yes("c")}, Config{}, tk, "CYBR", true)
	if out[0].Err == "" || out[2].Err == "" || out[1].Err != "" {
		t.Fatalf("errs: %q %q %q", out[0].Err, out[1].Err, out[2].Err)
	}
	recs := SeenRecords(out)
	if len(recs) != 1 || recs[0].Label != out[1].Request.Label() {
		t.Errorf("only the item that was filed may be recorded: %+v", recs)
	}
	if recs[0].Entry.Ticket == "" || recs[0].Entry.Verdict != Yes {
		t.Errorf("the record lacks the ticket or verdict: %+v", recs[0].Entry)
	}
}

func TestTheOldRecordFormatStillLoadsAndKeepsFirstReportedDate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	if err := os.WriteFile(path, []byte(`{"fleet-supplier-old":"2026-11-01T09:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSeen(path)
	if err != nil || !s.Has("fleet-supplier-old") || !s["fleet-supplier-old"].LastReceived.IsZero() {
		t.Fatalf("%v %v", s, err)
	}
	first := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	now := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	s.RecordEntry("fleet-supplier-old", SeenEntry{Verdict: Yes, LastReceived: now}, now)
	if !s["fleet-supplier-old"].Reported.Equal(first) || s["fleet-supplier-old"].Verdict != Yes {
		t.Errorf("first-reported date lost: %+v", s["fleet-supplier-old"])
	}
}

func TestNeedsListsWhatCodeFoundMissingAndNothingForANo(t *testing.T) {
	has := func(r Request, sub string) bool {
		for _, n := range r.Needs() {
			if strings.Contains(n, sub) {
				return true
			}
		}
		return false
	}
	base := sampleRequest(Unsure)
	linked := base
	linked.State, linked.Form = StateLinked, nil
	unreadable := base
	unreadable.State, unreadable.Form = StateUnreadable, nil
	none := base
	none.State, none.Form = StateNone, nil
	blank := base
	blank.Form = &Form{Name: "x", Notes: "  ", Missing: []string{"ERP", "Branch(es)/Markets Using Supplier"}}
	complete := sampleRequest(Unsure)
	if !has(linked, "Attach the supplier request form") || !has(unreadable, "not that form") || !has(none, "None was attached") {
		t.Error("a missing form was not asked for")
	}
	if !has(blank, "ERP, Branch(es)/Markets Using Supplier") || !has(blank, "goods or services") {
		t.Errorf("blank fields were not asked for: %v", blank.Needs())
	}
	if len(complete.Needs()) != 0 {
		t.Errorf("a complete form needs nothing: %v", complete.Needs())
	}
	if n := sampleRequest(No); len(n.Needs()) != 0 {
		t.Error("a No was asked for more")
	}
	none.Decision.Verdict = No
	if len(none.Needs()) != 0 {
		t.Error("a No with no form was asked for more")
	}
}

func TestTheItemAndTheCommentSayWhatIsStillNeededAndEscapeEverything(t *testing.T) {
	r := sampleRequest(Unsure)
	r.State, r.Form = StateLinked, nil
	d := TicketDescription(r, Config{}, "CYBR")
	for _, want := range []string{"h3. Information still needed", "Attach the supplier request form", "never contacts the requester", "judges the request again"} {
		if !strings.Contains(d, want) {
			t.Errorf("the item lacks %q:\n%s", want, d)
		}
	}
	r.Decision.Reason = "see {code} and [link|http://evil.example] !img.png!"
	c := UpdateComment(r, reportedAt(9), Config{})
	// Take out every backslash-escaped character: whatever is left of the reason
	// line must hold none of the characters that mean something in Jira markup.
	var why string
	for _, line := range strings.Split(c, "\n") {
		if strings.HasPrefix(line, "see ") {
			why = line
		}
	}
	if why == "" {
		t.Fatalf("the reason line is missing:\n%s", c)
	}
	left := regexp.MustCompile(`\\.`).ReplaceAllString(why, "")
	if strings.ContainsAny(left, "{}[]|!") {
		t.Errorf("an unescaped markup character survived in %q (left: %q)", why, left)
	}
}

func staffItem(id string) Item {
	r := sampleRequest(No)
	r.MessageID, r.ConversationID, r.From = id, "conv-"+id, "buyer@example.test"
	r.State, r.Form, r.Subject = StateNone, nil, "Pfister - PFI001"
	in := Input{MessageID: id, Sender: r.From, Subject: r.Subject, State: StateNone, Body: "Please merge the two vendor profiles"}
	return Item{Request: r, Input: Render(in, Config{}), Source: in.Source()}
}

func setAside(id string) []byte {
	return []byte(fmt.Sprintf(`{"schema":"cti-supplier/1","message_id":%q,"verdict":"not_request","reason":"merging records","evidence":["Please merge the two vendor profiles"]}`, id))
}

func TestFinishFilesNothingForASetAsideThreadButRecordsIt(t *testing.T) {
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{staffItem("s")}, map[int][]byte{0: setAside("s")}, staffCfg, tk, "CYBR", true)
	o := out[0]
	if o.Request.Decision.Verdict != NotRequest || o.Ticket != "" || len(tk.created) != 0 {
		t.Fatalf("%+v created %v", o, tk.created)
	}
	if recs := SeenRecords(out); len(recs) != 1 || recs[0].Entry.Verdict != NotRequest {
		t.Errorf("a set-aside thread must be recorded so it is not judged every day: %+v", recs)
	}
}

func TestAnItemFiledAsUnsureThenSetAsideGetsACommentNotASilentDrop(t *testing.T) {
	it := staffItem("s")
	it.Update, it.Prior = true, reportedAt(9) // was Unsure, with CYBR-7
	it.Request.LastReceived = time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	tk := &fakeTickets{}
	out := Finish(context.Background(), []Item{it}, map[int][]byte{0: setAside("s")}, staffCfg, tk, "CYBR", true)
	if out[0].Ticket != "commented" || len(tk.comments) != 1 || !strings.Contains(tk.comments[0], "not a request to set up a new supplier") {
		t.Fatalf("%+v comments %v", out[0], tk.comments)
	}
}

func TestEveryMessageInTheWindowIsListedWithWhatWasDoneWithIt(t *testing.T) {
	auto := msg("d1", "cd", "End User Digest: 1 New Message", "digest@example.test", "quarantine", 10, false)
	own := msg("o1", "co", "Supplier requests: 1", mailbox, "our own digest", 10, false)
	fresh := msg("m1", "c1", "new supplier", "a@example.test", "gravel", 12, false)
	oldMsg := msg("m0", "c0", "earlier supplier", "b@example.test", "paving", 9, false)
	reply := msg("m2", "c0", "Re: earlier supplier", "b@example.test", "thanks", 8, false)
	early := msg("m9", "c1", "context only", "a@example.test", "before the window", 1, false)
	early.Received = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	reported := Request{ConversationID: "c0", MessageID: "m0"}
	seen := Seen{reported.Label(): {LastReceived: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), Verdict: No}}
	auto2 := func(from, subject string) bool { return from == "digest@example.test" }
	c, err := CollectRead(context.Background(), fakeMail{[]graph.AddressedMessage{auto, own, fresh, oldMsg, reply, early}}, &perMessage{}, Policy{}, Config{}, seen, mailbox, epoch, auto2)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range c.Read {
		got[r.Subject] = r.Handling
	}
	want := map[string]string{
		"End User Digest: 1 New Message": HandledAutomatic,
		"new supplier":                   HandledNew,
		"earlier supplier":               HandledReported,
		"Re: earlier supplier":           HandledReported,
	}
	for subj, h := range want {
		if got[subj] != h {
			t.Errorf("%q handled as %q, want %q (all: %v)", subj, got[subj], h, got)
		}
	}
	if _, ok := got["Supplier requests: 1"]; ok {
		t.Error("the mailbox's own mail was listed as read")
	}
	if _, ok := got["context only"]; ok {
		t.Error("a message from before the window was listed: it was read for context, not in the window")
	}
	if len(c.Items) != 1 || c.Automatic != 1 {
		t.Errorf("items %d, automatic %d", len(c.Items), c.Automatic)
	}
}

func TestAnnotateSaysWhatCameOfEachMessage(t *testing.T) {
	req := func(conv, verdict string) Request {
		return Request{ConversationID: conv, MessageID: conv, Decision: Decision{Verdict: verdict}}
	}
	a, b, c, d := req("a", Unsure), req("b", Yes), req("c", No), req("d", Unsure)
	outs := []Outcome{
		{Request: a},
		{Request: b, Update: true, Changed: true},
		{Request: c, Update: true},
		{Request: d, Err: "jira down"},
	}
	t0 := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	rows := []MailRow{
		{Label: a.Label(), Received: t0, Handling: HandledNew},
		{Label: b.Label(), Received: t0.Add(time.Hour), Handling: HandledUpdate},
		{Label: c.Label(), Received: t0.Add(2 * time.Hour), Handling: HandledUpdate},
		{Label: d.Label(), Received: t0.Add(3 * time.Hour), Handling: HandledNew},
		{Received: t0.Add(4 * time.Hour), Handling: HandledAutomatic},
		{Label: "x", Received: t0.Add(5 * time.Hour), Handling: HandledReported},
	}
	got := Annotate(rows, outs)
	var results []string
	for _, r := range got {
		results = append(results, r.Result)
	}
	want := []string{"Reported earlier, nothing new", "Left out: automatic message from the mail filter",
		"Could not be filed, will be tried again", "New reply, judgement unchanged (not critical)", "Updated: critical", "Unsure"}
	if strings.Join(results, "|") != strings.Join(want, "|") {
		t.Errorf("results (newest first)\n got %q\nwant %q", results, want)
	}
	if rows[0].Result != "" {
		t.Error("Annotate changed the slice it was given")
	}
}
