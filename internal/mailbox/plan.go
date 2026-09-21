package mailbox

import (
	"fmt"
	"sort"
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
//  1. No record of the agent having read it -> leave. Absolute. This is the
//     operator's "make sure a given email has been processed" rule, and it is
//     checked first so that no later rule can override it.
//  2. Carries a CVE -> archive, never delete. A message that contributed a
//     finding is evidence; it goes to Archive whatever else it looks like.
//  3. Declared an auto-reply by its own headers -> Deleted Items.
//  4. Anything else -> leave.
//
// Rule 2 sits above rule 3 deliberately. An out-of-office reply quoting an
// advisory in its body would match both, and archiving something that should
// have been deleted is a tidiness failure, whereas deleting a genuine advisory
// is a loss.
//
// # WHY RULE 4 IS "LEAVE" AND NOT "ARCHIVE"
//
// It used to be archive, and the first real dry run showed what that means.
// This is a shared security mailbox: alongside the advisories it receives
// user-reported phishing, Defender alerts, scan notifications and ordinary
// mail from colleagues. The plan proposed archiving a message whose entire
// subject was "suspicious", a forwarded invoice, and an alert about a
// potential attack path - all with the reason "processed, no CVE, not an
// automatic reply".
//
// "The agent read it looking for CVEs and found none" and "this has been
// dealt with" are different facts, and only the first one is in the
// processed-message log. Filing away a colleague's phishing report before
// anybody triaged it is precisely the quiet damage this package's own doc
// comment warns about, and the operator asked for the CTI emails to be
// archived - not for everything the agent happened to glance at.
//
// So the default is now to do nothing, which also makes the rules match what
// was actually asked for: CTI mail is archived, out-of-office replies are
// deleted, everything else is somebody's job. The leave count feeds
// BacklogNote, so mail accumulating here is reported rather than silently
// tidied.
func Plan(candidates []Candidate, processed map[string]Processed) []Decision {
	out := make([]Decision, 0, len(candidates))
	for _, c := range candidates {
		rec, ok := processed[c.ID]
		switch {
		case !ok:
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: "no record that a completed run has read this message"})
		case rec.HasCVE:
			out = append(out, Decision{Candidate: c, Action: ActionArchive,
				Reason: "processed and carried at least one CVE", Known: true})
		case rec.AutoReply || c.AutoReply:
			out = append(out, Decision{Candidate: c, Action: ActionDelete,
				Reason: "processed, no CVE, and the sending system declared it " +
					"an automatic reply", Known: true})
		default:
			out = append(out, Decision{Candidate: c, Action: ActionLeave,
				Reason: "read by the agent but carried no CVE, so it is not a " +
					"CTI advisory this lane is responsible for - could be a " +
					"reported phish, an alert or a person writing to the team",
				Known: true})
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
