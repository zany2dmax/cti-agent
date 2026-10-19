package mailbox

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Action is what the cleanup lane proposes to do with one message.
type Action string

const (
	// ActionArchive is for a message a completed run processed.
	ActionArchive Action = "archive"
	// ActionDelete moves to Deleted Items. Recoverable; nothing here purges.
	ActionDelete Action = "delete"
	// ActionLeave is the default and the only outcome for anything the agent
	// has no record of reading.
	ActionLeave Action = "leave"
)

// Candidate is a message currently in the inbox, as the lane sees it.
type Candidate struct {
	ID        string
	Subject   string
	Received  time.Time
	AutoReply bool // as declared by the sending system's headers

	// SelfSent means the fleet sent this message itself - a digest, a weekly,
	// a Patch Tuesday synopsis - and it came back because the reports are
	// delivered to the same mailbox they are read from.
	//
	// It has to be here, not inferred later. The digest lane now skips its own
	// mail before recording anything, so these messages have no entry in the
	// processed log. Rule 1 below would therefore leave them forever, the
	// inbox would fill with our own reports, and at the backlog threshold the
	// lane would escalate "the agent has stopped reading the mailbox" about a
	// mailbox it was reading perfectly well.
	SelfSent bool
}

// Decision pairs a candidate with what will happen to it and why.
//
// Reason is not decoration. This lane moves other people's mail on a schedule
// with nobody watching, so every action has to be explainable after the fact
// from the log alone - "why is this in Deleted Items" needs an answer that is
// not "the agent decided".
type Decision struct {
	Candidate
	Action Action
	Reason string

	// Known records whether the processed-message log had an entry for this
	// message. It exists because "leave" now has two causes that mean
	// opposite things: the agent never read it (which may mean the agent has
	// stopped reading the mailbox), or the agent read it and it simply is not
	// a CTI advisory (which is normal and permanent). Counting both as one
	// number would make the backlog alarm fire on a healthy mailbox, and
	// deriving the difference from the Reason string afterwards would be
	// parsing our own prose.
	Known bool
}

// Plan decides what to do with each candidate.
//
// THE RULES, IN THIS ORDER, AND THE ORDER MATTERS
//
//  0. Sent by this fleet -> archive. Our own reports are never processed (the
//     digest skips them), so no later rule could ever move them.
//  1. An automatic reply -> Deleted Items, read or not. Declared by its own
//     headers, or - since 1.3.2 - by a subject that starts the way an
//     out-of-office does ("Automatic reply:", "Out of Office:" ...).
//  2. No record of a lane having read it -> leave.
//  3. Read by the lane that OWNS it -> archive, after the grace. The digest
//     owns what it took a CVE from; cti-appscan owns the Qualys WAS
//     notifications its weekly reported on (Processed.Owner).
//  4. Anything else -> leave.
//
// # WHY AUTO-REPLIES MOVED ABOVE THE PROCESSED RULE (1.3.2)
//
// The operator's instruction: automatic replies should always just go to
// Deleted Items. Below rule 2 they only went when the digest happened to have
// recorded them, so every out-of-office arriving after the morning read - and
// every one on a day the lane did not run - stayed in the inbox for good.
// "Processed first" exists to protect mail somebody may need; nobody needs a
// bounce, and Deleted Items is recoverable.
//
// The subject match is deliberately narrow (a prefix, not a substring) and
// has one exception: a subject-only match the digest took a CVE from is
// archived, not deleted. Anyone can title a message "Automatic reply:", and
// a real advisory filed under that subject is evidence. A message whose
// HEADERS say auto-reply is deleted whatever it quoted - that is the sending
// system's own declaration.
//
// # WHY RULE 4 IS "LEAVE" AND NOT "ARCHIVE"
//
// This is a shared security mailbox: alongside the advisories it receives
// user-reported phishing, Defender alerts, scan notifications and ordinary
// mail from colleagues. The first real dry run of an "archive whatever was
// read" rule proposed filing a message whose whole subject was "suspicious",
// a forwarded invoice, and an attack-path alert. "A lane read it" is not
// "this has been dealt with" - only the lane that OWNS a kind of mail can say
// it has been, so only an owner's record archives (the operator's rule since
// 1.3.2: archive once the right lane has seen it). The leave count feeds
// BacklogNote, so mail accumulating here is reported rather than tidied.
func Plan(candidates []Candidate, processed map[string]Processed,
	now time.Time, minAge time.Duration) []Decision {
	return PlanWith(candidates, processed, Options{Now: now, MinAge: minAge})
}

// Options tune a plan.
type Options struct {
	Now time.Time
	// MinAge is the archive grace: an owned message stays in the inbox until
	// it is this old, so the outcome does not depend on when the lane runs.
	// It applies to archiving only; auto-replies go on sight.
	MinAge time.Duration
	// SubjectGrace holds a SUBJECT-only auto-reply match that no lane has
	// read yet until it is this old (cti-mailbox passes GRAPH_LOOKBACK). The
	// CVE exception below can only protect a message the digest has read; a
	// real advisory titled "Automatic reply: ..." arriving just before the
	// cleanup would otherwise be deleted before the digest ever saw it.
	// Header-declared auto-replies are not held.
	SubjectGrace time.Duration
	// HoldArchive, when set, turns every archive except our own reports into
	// a leave with this as the reason. cti-mailbox sets it on a day no CTI
	// email was processed: the fleet may not be reading the mailbox, so
	// nothing is filed away - but auto-replies are still deleted, which needs
	// no fleet health at all.
	HoldArchive string
}

// autoReplyPrefixes are subject openings out-of-office systems use. Matched
// at the start of the subject, case-insensitively, after any spaces.
var autoReplyPrefixes = []string{
	"automatic reply:",
	"auto reply:", "auto-reply:", "autoreply:", "auto response:",
	"auto-response:", "autoresponse:",
	"out of office:", "out of office reply:", "out-of-office:",
	"automatische antwort:", "réponse automatique :", "réponse automatique:",
	"respuesta automática:",
}

// AutoReplySubject reports whether a subject starts like an out-of-office.
func AutoReplySubject(subject string) bool {
	s := strings.ToLower(strings.TrimSpace(subject))
	for _, p := range autoReplyPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// PlanWith is Plan with every option.
func PlanWith(candidates []Candidate, processed map[string]Processed, o Options) []Decision {
	now, minAge := o.Now, o.MinAge
	out := make([]Decision, 0, len(candidates))
	for _, c := range candidates {
		rec, ok := processed[c.ID]
		headerAuto := c.AutoReply || (ok && rec.AutoReply)
		subjectAuto := AutoReplySubject(c.Subject)
		owner := ""
		switch {
		case ok && rec.Owner != "":
			owner = rec.Owner
		case ok && rec.HasCVE:
			owner = "digest"
		}
		switch {
		case c.SelfSent:
			out = append(out, Decision{Candidate: c, Action: ActionArchive,
				Reason: "sent by this fleet - our own report delivered back to " +
					"the mailbox it is read from", Known: true})
		case headerAuto:
			out = append(out, Decision{Candidate: c, Action: ActionDelete,
				Reason: "the sending system's headers declare it an automatic reply",
				Known:  ok})
		case subjectAuto && !ok && o.SubjectGrace > 0 && c.Received.After(now.Add(-o.SubjectGrace)):
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: "the subject looks like an automatic reply, but no lane has " +
					"read it yet - it waits for the digest in case it is a real advisory"})
		case subjectAuto && !(ok && rec.HasCVE):
			out = append(out, Decision{Candidate: c, Action: ActionDelete,
				Reason: "the subject marks it an automatic reply",
				Known:  ok})
		case !ok:
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: "no record that a completed run has read this message"})
		case owner == "":
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: "read by the agent but no lane owns it - not a CTI " +
					"advisory or a scan notification; could be a reported " +
					"phish, an alert or a person writing to the team",
				Known: true})
		case o.HoldArchive != "":
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: o.HoldArchive, Known: true})
		case minAge > 0 && c.Received.After(now.Add(-minAge)):
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: fmt.Sprintf(
					"%s, but only %s old - it stays in the inbox until %s so "+
						"the team can still read it there",
					ownedBy(owner), now.Sub(c.Received).Round(time.Minute), minAge),
				Known: true})
		default:
			out = append(out, Decision{Candidate: c, Action: ActionArchive,
				Reason: ownedBy(owner), Known: true})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Received.Before(out[j].Received)
	})
	return out
}

func ownedBy(owner string) string {
	switch owner {
	case "digest":
		return "processed and carried at least one CVE"
	case OwnerAppScan:
		return "a scan notification the application-security weekly reported on"
	default:
		return "read by the " + owner + " lane, which owns it"
	}
}

// Counts summarises a plan.
type Counts struct {
	Archive int
	Delete  int
	Leave   int

	// Unread is the subset of Leave the agent has no record of reading. It is
	// the only number here that can indicate a fault: mail the agent read and
	// left alone is a security team's ordinary inbox, while mail it never read
	// piling up is what "the digest succeeds every morning and reads nothing"
	// looks like from outside.
	Unread int
}

func Summarise(plan []Decision) Counts {
	var c Counts
	for _, d := range plan {
		switch d.Action {
		case ActionArchive:
			c.Archive++
		case ActionDelete:
			c.Delete++
		case ActionLeave:
			c.Leave++
			if !d.Known {
				c.Unread++
			}
		}
	}
	return c
}

// BacklogNote explains an unprocessed backlog, or returns empty when there is
// nothing worth saying.
//
// A growing count of mail the agent has never read is the interesting signal
// here, and not because of tidiness: the mailbox filling up with unprocessed
// messages is what "the agent stopped reading the mailbox" looks like from the
// outside. The digest failing is loud. The digest succeeding every morning
// while silently reading nothing is not, and this is the check that catches
// it.
func BacklogNote(c Counts, threshold int) string {
	// c.Unread, not c.Leave. Once "read but not a CTI advisory" became a
	// leave, c.Leave started counting a healthy security mailbox's ordinary
	// traffic, and this alarm would have fired every day on a working fleet -
	// an alert that is always on is an alert nobody reads.
	if threshold <= 0 || c.Unread < threshold {
		return ""
	}
	return fmt.Sprintf(
		"%d message(s) in the inbox have no processing record, at or above the "+
			"threshold of %d. Cleanup left them alone, which is correct, but a "+
			"growing backlog usually means messages are arriving outside the "+
			"agent's lookback window - or that it has stopped reading the "+
			"mailbox while still reporting success.", c.Unread, threshold)
}
