package supplier

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// This file is the lane's spine, kept free of Graph and Jira clients so every
// decision in it is tested against fakes: which messages are one request, which
// message carries it, whether its form was read, linked or missing, and what is
// filed. The command in cmd/cti-supplier supplies the real clients.

// Mail is the read-only view of the mailbox the lane needs.
type Mail interface {
	// Addressed returns the messages received since a time that have the
	// supplier-request address in To or Cc.
	Addressed(ctx context.Context, since time.Time) ([]graph.AddressedMessage, error)
}

// Item is one new request the lane collected: the request as far as code could
// establish it, and the input the model is shown.
type Item struct {
	Request Request `json:"request"`
	// Update is true when the request was reported before and has a newer
	// message now; Prior is what was remembered about it.
	Update bool      `json:"update,omitempty"`
	Prior  SeenEntry `json:"prior,omitempty"`
	// Input is the rendered file for the model.
	Input string `json:"input"`
	// Source is the untrusted text, kept so evidence can be checked at finish.
	Source string `json:"source"`
	// Messages are the thread's messages the lane read, for the record the
	// mailbox cleanup uses (see OwnedRefs).
	Messages []MsgRef `json:"messages,omitempty"`
}

// MsgRef names one message, enough for the cleanup lane's record of mail the
// supplier lane owns.
type MsgRef struct {
	ID       string    `json:"id"`
	Subject  string    `json:"subject"`
	Received time.Time `json:"received"`
}

func refs(t thread) []MsgRef {
	out := make([]MsgRef, 0, len(t))
	for _, m := range t {
		out = append(out, MsgRef{ID: m.ID, Subject: oneLine(m.Subject, 100), Received: m.Received})
	}
	return out
}

// settled says whether a request has been dealt with, so its mail may be filed
// away: it was judged not critical, or it is critical or unsure and has its
// Kanban item. A request set aside as not being a supplier request is not
// settled: that thread is for a person, and stays in the inbox. Nothing unknown
// (an old record with no verdict, an item that failed to file) is settled.
func settled(verdict, ticket string) bool {
	switch verdict {
	case No:
		return true
	case Yes, Unsure:
		return strings.TrimSpace(ticket) != ""
	}
	return false
}

// SettledEntry is settled for a remembered request.
func SettledEntry(e SeenEntry) bool { return settled(e.Verdict, e.Ticket) }

// linkRE finds a form that was shared as a link instead of attached.
var linkRE = regexp.MustCompile(`(?i)(sharepoint\.com|onedrive|1drv\.ms)`)

// namedFormRE finds a spreadsheet named in the text. When no form could be read
// from the attachments, a name like that is a form shared as a link: Graph's
// text rendering drops the link and keeps the name.
var namedFormRE = regexp.MustCompile(`(?i)\b[\w .()\-]+\.xls[xm]\b`)

func isReply(subject string) bool {
	s := strings.ToLower(strings.TrimSpace(subject))
	return strings.HasPrefix(s, "re:") || strings.HasPrefix(s, "fw:") || strings.HasPrefix(s, "fwd:")
}

// thread is the messages of one conversation, oldest first.
type thread []graph.AddressedMessage

// group splits messages into conversations, each oldest first, the conversations
// oldest first. A message with no conversation id is a conversation of its own.
func group(msgs []graph.AddressedMessage) []thread {
	by := map[string]thread{}
	var keys []string
	for _, m := range msgs {
		k := m.ConversationID
		if k == "" {
			k = "msg:" + m.ID
		}
		if _, ok := by[k]; !ok {
			keys = append(keys, k)
		}
		by[k] = append(by[k], m)
	}
	out := make([]thread, 0, len(keys))
	for _, k := range keys {
		t := by[k]
		sort.SliceStable(t, func(i, j int) bool { return t[i].Received.Before(t[j].Received) })
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i][0].Received.Before(out[j][0].Received) })
	return out
}

// maxReplies bounds how many later messages of a thread are shown to the model.
const maxReplies = 5

// contextLookback is how far before the window the lane reads, so a thread that
// has new activity in the window is judged with its earlier messages - the one
// that carries the form is usually the first, and a window that started after it
// would judge the request on a reply that says only "Approved".
const contextLookback = 21 * 24 * time.Hour

// Handling is what the lane did with a message it read.
const (
	HandledNew       = "new"       // a new request, judged
	HandledUpdate    = "update"    // a reported request with a newer message, judged again
	HandledReported  = "reported"  // a request reported before, nothing newer
	HandledAutomatic = "automatic" // one of the fleet's own machine senders, left out
)

// MailRow is one message the lane read in the window, for the digest's list of
// emails read. Handling is set at collect; Result is filled in at finish, when
// the verdicts exist (see Annotate).
type MailRow struct {
	Label    string    `json:"label,omitempty"`
	Received time.Time `json:"received"`
	From     string    `json:"from"`
	Subject  string    `json:"subject"`
	Handling string    `json:"handling"`
	Result   string    `json:"result,omitempty"`
}

// Collected is what one collect pass found.
type Collected struct {
	Items []Item
	// Automatic counts the machine-sender messages inside the window.
	Automatic int
	// Read lists every message inside the window that the lane looked at, including
	// the automatic ones and the ones already reported, so the digest can answer
	// "what did it actually read?".
	Read []MailRow
	// Settled holds the messages of requests reported earlier that were dealt
	// with (see settled) and have nothing newer: the cleanup may file them away.
	Settled []MsgRef
}

// Collect finds the new supplier requests: see CollectRead. It returns the items
// and the count of automatic messages left out.
func Collect(ctx context.Context, mail Mail, src Source, p Policy, cfg Config, seen Seen, mailbox string, since time.Time, isAutomatic func(from, subject string) bool) ([]Item, int, error) {
	c, err := CollectRead(ctx, mail, src, p, cfg, seen, mailbox, since, isAutomatic)
	return c.Items, c.Automatic, err
}

// CollectRead finds the new supplier requests: threads addressed to the list that
// have a message since the given time and whose label is not in seen. Each
// thread is read whole, back to contextLookback before that time. It reads each
// thread's form through ReadForms, the only path to attachment bytes, and
// builds the model's input. It changes nothing in the mailbox.
//
// isAutomatic says whether a message is one of the fleet's own machine senders
// (the mail filter's quarantine digest): such a message is not a request and is
// left out, and the Automatic count is those inside the window so the digest
// can say how many were skipped. It decides by sender address and subject only,
// never by what a message says, so nothing a requester writes can use it.
//
// Read records each message inside the window (not the older ones read for
// context) with what was done with it. The mailbox's own mail is not listed.
func CollectRead(ctx context.Context, mail Mail, src Source, p Policy, cfg Config, seen Seen, mailbox string, since time.Time, isAutomatic func(from, subject string) bool) (Collected, error) {
	var out Collected
	msgs, err := mail.Addressed(ctx, since.Add(-contextLookback))
	if err != nil {
		return Collected{}, fmt.Errorf("reading the mailbox: %w", err)
	}
	row := func(m graph.AddressedMessage, label, handling string) MailRow {
		return MailRow{Label: label, Received: m.Received, From: m.From, Subject: m.Subject, Handling: handling}
	}
	for _, t := range group(msgs) {
		// The fleet's own mail is not a request, and neither is its quarantine digest.
		var mine thread
		for _, m := range t {
			switch {
			case strings.EqualFold(strings.TrimSpace(m.From), strings.TrimSpace(mailbox)):
			case isAutomatic != nil && isAutomatic(m.From, m.Subject):
				if !m.Received.Before(since) {
					out.Automatic++
					out.Read = append(out.Read, row(m, "", HandledAutomatic))
				}
			default:
				mine = append(mine, m)
			}
		}
		if len(mine) == 0 {
			continue
		}
		// Only a thread with something new in the window is a candidate; the
		// older messages are there for context, not to bring back an old thread.
		if mine[len(mine)-1].Received.Before(since) {
			continue
		}
		it, err := buildItem(ctx, mine, src, p, cfg)
		if err != nil {
			return Collected{}, err
		}
		label := it.Request.Label()
		handling := HandledNew
		// A request reported before is skipped unless a message newer than the one
		// last judged has arrived: that is new information, and it is judged again
		// (a request recorded without a last-received time is reported once only).
		if prior, ok := seen[label]; ok {
			if prior.LastReceived.IsZero() || !it.Request.LastReceived.After(prior.LastReceived) {
				handling = HandledReported
				if SettledEntry(prior) {
					out.Settled = append(out.Settled, refs(mine)...)
				}
			} else {
				handling = HandledUpdate
				it.Update, it.Prior = true, prior
			}
		}
		for _, m := range mine {
			if !m.Received.Before(since) {
				out.Read = append(out.Read, row(m, label, handling))
			}
		}
		if handling != HandledReported {
			out.Items = append(out.Items, it)
		}
	}
	return out, nil
}

func buildItem(ctx context.Context, t thread, src Source, p Policy, cfg Config) (Item, error) {
	req := Request{ConversationID: t[0].ConversationID, State: StateNone}
	primary := t[0]
	var skipped []Skipped
	sawUnreadable := false
	var unreadableMsg *graph.AddressedMessage

	for i := range t {
		m := t[i]
		if !m.HasAttachments {
			continue
		}
		reads, sk, err := ReadForms(ctx, src, p, m.ID)
		if err != nil {
			return Item{}, fmt.Errorf("reading the attachments of %q: %w", oneLine(m.Subject, 60), err)
		}
		skipped = append(skipped, sk...)
		for _, r := range reads {
			if r.Err == nil {
				f := r.Form
				req.State, req.Form, primary = StateRead, &f, m
				break
			}
			sawUnreadable = true
			if unreadableMsg == nil {
				unreadableMsg = &t[i]
			}
		}
		if req.State == StateRead {
			break
		}
	}
	if req.State != StateRead {
		linked := false
		for _, m := range t {
			if linkRE.MatchString(m.BodyText) || namedFormRE.MatchString(m.BodyText) {
				linked = true
			}
		}
		switch {
		case sawUnreadable:
			req.State, primary = StateUnreadable, *unreadableMsg
		case linked:
			req.State = StateLinked
			for _, m := range t {
				if !isReply(m.Subject) {
					primary = m
					break
				}
			}
		default:
			for _, m := range t {
				if !isReply(m.Subject) {
					primary = m
					break
				}
			}
		}
	}

	req.MessageID, req.Subject, req.From, req.Received = primary.ID, primary.Subject, primary.From, primary.Received
	req.LastReceived = t[len(t)-1].Received
	req.Skipped = skipped

	body := primary.BodyText
	var replies []string
	for _, m := range t {
		if m.ID == primary.ID || len(replies) >= maxReplies {
			continue
		}
		replies = append(replies, fmt.Sprintf("REPLY from %s: %s", m.From, oneLine(m.BodyText, 1000)))
	}
	if len(replies) > 0 {
		body += "\n\n" + strings.Join(replies, "\n")
	}
	in := Input{MessageID: req.MessageID, Received: req.Received.UTC().Format(time.RFC3339),
		Sender: req.From, Subject: req.Subject, Body: body, State: req.State, Form: req.Form}
	return Item{Request: req, Input: Render(in, cfg), Source: in.Source(), Messages: refs(t)}, nil
}

// Tickets is what the lane needs from Jira.
type Tickets interface {
	// Find returns the item already filed for a request, in any state.
	Find(ctx context.Context, jql string) (key, url string, found bool, err error)
	// Create files one item and returns its key and link.
	Create(ctx context.Context, summary, description string, labels []string) (key, url string, err error)
	// Comment adds a comment to an existing item. The lane never closes,
	// reopens or edits an item: that stays with a person.
	Comment(ctx context.Context, key, text string) error
}

// Outcome is one request after judgement, with what happened to its item.
type Outcome struct {
	Request Request
	// Ticket is "" (none needed), "found", "created", "commented", "unchanged",
	// "would-create", "would-comment" or "error".
	Ticket string
	// Err is the reason an item could not be filed or updated.
	Err string
	// Update is true for a request reported before; Changed is true when the new
	// judgement or form state differs from the last, which is what is acted on.
	Update, Changed bool
}

// Reported says whether the digest should list this outcome: every new request,
// and an update only when something changed.
func (o Outcome) Reported() bool { return !o.Update || o.Changed }

// Finish judges every item and files or updates the Kanban items that need it.
//
// results holds the model's raw output by item index; an item with none is
// Unsure, so a model that is down turns every request into a to-do for a
// person. tickets may be nil (no Jira configured) and fileJira false (a dry
// run) - either way nothing is written. A failure on one item is recorded on
// that item and does not stop the others or the digest.
//
// A request reported before (an Update) is acted on only when its judgement or
// its form state changed: a comment is added to the item it already has, saying
// what changed. Nothing is ever closed, reopened or edited.
func Finish(ctx context.Context, items []Item, results map[int][]byte, cfg Config, tickets Tickets, project string, fileJira bool) []Outcome {
	out := make([]Outcome, 0, len(items))
	for i, it := range items {
		req := it.Request
		raw, ok := results[i]
		if !ok || len(raw) == 0 {
			req.Decision = Decision{Verdict: Unsure,
				Reason: "No judgement was available for this request, so it needs a person.",
				Notes:  []string{"no model judgement was run"}}
		} else {
			in := Input{MessageID: req.MessageID, Sender: req.From, Subject: req.Subject, State: req.State, Form: req.Form}
			req.Decision = judgeAgainst(raw, in, it.Source, cfg)
		}

		o := Outcome{Request: req, Update: it.Update}
		if it.Update {
			o.Changed = it.Prior.Verdict != req.Decision.Verdict ||
				(it.Prior.FormState != StateRead && req.State == StateRead)
			o.Request.PriorVerdict = it.Prior.Verdict
			o.Request.TicketKey, o.Request.TicketURL = it.Prior.Ticket, it.Prior.TicketURL
		}
		switch {
		case it.Update && !o.Changed:
			o.Ticket = "unchanged"
		case it.Update && it.Prior.Ticket != "":
			o.Request.Updated = true
			switch {
			case tickets == nil || project == "":
				o.Ticket, o.Err = "error", "no Jira project is set for this lane (SUPPLIER_JIRA_PROJECT)"
			case !fileJira:
				o.Ticket = "would-comment"
			default:
				if err := tickets.Comment(ctx, it.Prior.Ticket, UpdateComment(o.Request, it.Prior, cfg)); err != nil {
					o.Ticket, o.Err = "error", "commenting on "+it.Prior.Ticket+": "+err.Error()
				} else {
					o.Ticket = "commented"
				}
			}
		default:
			o.Request.Updated = it.Update
			if req.NeedsTicket(false) {
				o.fileTicket(ctx, tickets, project, fileJira, cfg)
			}
		}
		out = append(out, o)
	}
	return out
}

// fileTicket finds the item already filed for the request or files one.
func (o *Outcome) fileTicket(ctx context.Context, tickets Tickets, project string, fileJira bool, cfg Config) {
	req := o.Request
	switch {
	case tickets == nil || project == "":
		o.Ticket, o.Err = "error", "no Jira project is set for this lane (SUPPLIER_JIRA_PROJECT)"
	case !fileJira:
		o.Ticket = "would-create"
	default:
		key, url, found, err := tickets.Find(ctx, FindJQL(project, req))
		switch {
		case err != nil:
			o.Ticket, o.Err = "error", "looking for an existing item: "+err.Error()
		case found:
			o.Ticket = "found"
			o.Request.TicketKey, o.Request.TicketURL = key, url
		default:
			key, url, err := tickets.Create(ctx, TicketSummary(req), TicketDescription(req, cfg, project), req.Labels())
			if err != nil {
				o.Ticket, o.Err = "error", "creating the item: "+err.Error()
			} else {
				o.Ticket = "created"
				o.Request.TicketKey, o.Request.TicketURL = key, url
			}
		}
	}
}

// SeenRecords is what to remember after a send: every outcome that did not
// fail. One whose item could not be filed or commented is left out, so the next
// run collects it again and tries again instead of the lane believing it done.
func SeenRecords(outs []Outcome) []SeenRecord {
	out := []SeenRecord{}
	for _, o := range outs {
		if o.Err != "" {
			continue
		}
		r := o.Request
		out = append(out, SeenRecord{Label: r.Label(), Entry: SeenEntry{
			LastReceived: r.LastReceived, Verdict: r.Decision.Verdict, FormState: r.State,
			Ticket: r.TicketKey, TicketURL: r.TicketURL,
		}})
	}
	return out
}

// judgeAgainst is Judge with the evidence checked against the exact text the
// model was shown, which Collect stored, rather than a rebuild of it.
func judgeAgainst(raw []byte, in Input, source string, cfg Config) Decision {
	return judge(raw, in, source, cfg)
}

// OwnedRefs returns the messages of the requests this run dealt with, for the
// mailbox cleanup to file away: a request judged not critical, or critical or
// unsure with its item in hand, and not one that failed to file or was set
// aside. outs is Finish's result for items, in the same order.
func OwnedRefs(items []Item, outs []Outcome) []MsgRef {
	var out []MsgRef
	for i, o := range outs {
		if i >= len(items) || o.Err != "" {
			continue
		}
		if settled(o.Request.Decision.Verdict, o.Request.TicketKey) {
			out = append(out, items[i].Messages...)
		}
	}
	return out
}

// Requests returns the requests of a set of outcomes, for the digest.
func Requests(outs []Outcome) []Request {
	out := make([]Request, 0, len(outs))
	for _, o := range outs {
		if !o.Reported() {
			continue
		}
		out = append(out, o.Request)
	}
	return out
}

// Annotate fills in what each message of the list came to, from the finished
// outcomes: the verdict for a request judged now, a plain note for one reported
// earlier, one that could not be filed, or a machine sender. It returns a new
// slice, newest message first.
func Annotate(rows []MailRow, outs []Outcome) []MailRow {
	by := map[string]Outcome{}
	for _, o := range outs {
		by[o.Request.Label()] = o
	}
	res := make([]MailRow, len(rows))
	copy(res, rows)
	for i := range res {
		r := &res[i]
		switch r.Handling {
		case HandledAutomatic:
			r.Result = "Left out: automatic message from the mail filter"
			continue
		case HandledReported:
			r.Result = "Reported earlier, nothing new"
			continue
		}
		o, ok := by[r.Label]
		switch {
		case !ok:
			r.Result = "Not judged"
		case o.Err != "":
			r.Result = "Could not be filed, will be tried again"
		case o.Update && !o.Changed:
			r.Result = "New reply, judgement unchanged (" + strings.ToLower(VerdictLabel(o.Request.Decision.Verdict)) + ")"
		case o.Update:
			r.Result = "Updated: " + strings.ToLower(VerdictLabel(o.Request.Decision.Verdict))
		default:
			r.Result = VerdictLabel(o.Request.Decision.Verdict)
		}
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Received.After(res[j].Received) })
	return res
}
