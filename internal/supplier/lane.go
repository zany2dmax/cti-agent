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
	// Input is the rendered file for the model.
	Input string `json:"input"`
	// Source is the untrusted text, kept so evidence can be checked at finish.
	Source string `json:"source"`
}

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

// Collect finds the new supplier requests: threads addressed to the list that
// have a message since the given time and whose label is not in seen. Each
// thread is read whole, back to contextLookback before that time. It reads each
// thread's form through ReadForms, the only path to attachment bytes, and
// builds the model's input. It changes nothing in the mailbox.
func Collect(ctx context.Context, mail Mail, src Source, p Policy, cfg Config, seen map[string]bool, mailbox string, since time.Time) ([]Item, error) {
	msgs, err := mail.Addressed(ctx, since.Add(-contextLookback))
	if err != nil {
		return nil, fmt.Errorf("reading the mailbox: %w", err)
	}
	var items []Item
	for _, t := range group(msgs) {
		// The fleet's own mail is not a request.
		var mine thread
		for _, m := range t {
			if !strings.EqualFold(strings.TrimSpace(m.From), strings.TrimSpace(mailbox)) {
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
			return nil, err
		}
		if seen[it.Request.Label()] {
			continue
		}
		items = append(items, it)
	}
	return items, nil
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
	return Item{Request: req, Input: Render(in, cfg), Source: in.Source()}, nil
}

// Tickets is what the lane needs from Jira.
type Tickets interface {
	// Find returns the item already filed for a request, in any state.
	Find(ctx context.Context, jql string) (key, url string, found bool, err error)
	// Create files one item and returns its key and link.
	Create(ctx context.Context, summary, description string, labels []string) (key, url string, err error)
}

// Outcome is one request after judgement, with what happened to its item.
type Outcome struct {
	Request Request
	// Ticket is "" (none needed), "found", "created", "would-create" or "error".
	Ticket string
	// Err is the reason an item could not be filed.
	Err string
}

// Finish judges every item and files the Kanban items that need filing.
//
// results holds the model's raw output by item index; an item with none is
// Unsure, so a model that is down turns every request into a to-do for a
// person. tickets may be nil (no Jira configured) and fileJira false (a dry
// run) - either way nothing is written. A failure to file one item is recorded
// on that item and does not stop the others or the digest.
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

		o := Outcome{Request: req}
		if req.NeedsTicket(false) {
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
		out = append(out, o)
	}
	return out
}

// judgeAgainst is Judge with the evidence checked against the exact text the
// model was shown, which Collect stored, rather than a rebuild of it.
func judgeAgainst(raw []byte, in Input, source string, cfg Config) Decision {
	return judge(raw, in, source, cfg)
}

// Requests returns the requests of a set of outcomes, for the digest.
func Requests(os []Outcome) []Request {
	out := make([]Request, len(os))
	for i, o := range os {
		out[i] = o.Request
	}
	return out
}
