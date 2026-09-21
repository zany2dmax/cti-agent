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
//  4. Anything else that was processed -> archive.
//
// Rule 2 sits above rule 3 deliberately. An out-of-office reply quoting an
// advisory in its body would match both, and archiving something that should
// have been deleted is a tidiness failure, whereas deleting a genuine advisory
// is a loss.
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
				Reason: "processed and carried at least one CVE"})
		case rec.AutoReply || c.AutoReply:
			out = append(out, Decision{Candidate: c, Action: ActionDelete,
				Reason: "processed, no CVE, and the sending system declared it " +
					"an automatic reply"})
		default:
			out = append(out, Decision{Candidate: c, Action: ActionArchive,
				Reason: "processed, no CVE, not an automatic reply"})
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
	if threshold <= 0 || c.Leave < threshold {
		return ""
	}
	return fmt.Sprintf(
		"%d message(s) in the inbox have no processing record, at or above the "+
			"threshold of %d. Cleanup left them alone, which is correct, but a "+
			"growing backlog usually means messages are arriving outside the "+
			"agent's lookback window - or that it has stopped reading the "+
			"mailbox while still reporting success.", c.Leave, threshold)
}
