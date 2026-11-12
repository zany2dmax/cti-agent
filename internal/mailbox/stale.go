package mailbox

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ActionUnhandled moves a message into the stale sweep's own folder
// ("Unhandled" by default): not Archive, which means a lane handled it, and
// not Deleted Items. Nothing here deletes by age.
const ActionUnhandled Action = "unhandled"

// StaleCandidate is a message older than the stale cutoff, as the sweep sees
// it: past every lane's window and past the daily plan's, so no rule there
// will ever move it.
type StaleCandidate struct {
	ID       string
	Subject  string
	Received time.Time
	Flagged  bool
}

// PlanStale decides the stale sweep: every message moves to the Unhandled
// folder except one a person flagged.
//
// # WHY BY AGE ALONE, AND WHY NOT ARCHIVE
//
// By the time a message is this old, the processed records that could say
// what it was have expired (DefaultRetain), so there is nothing left to
// judge it by - and judging by sender or subject is exactly what this lane
// refuses to do anywhere else. So the sweep does not decide what a message
// is. It moves everything old into one folder whose name says "nobody here
// dealt with this", where a person can look, and the weekly summary says how
// many went. Archive would claim a lane handled it; Deleted Items would
// hide it. A flag is a person's "I am on this", and the sweep leaves it.
func PlanStale(c []StaleCandidate, now time.Time, age time.Duration, folder string) []Decision {
	out := make([]Decision, 0, len(c))
	for _, m := range c {
		d := Decision{Candidate: Candidate{ID: m.ID, Subject: m.Subject, Received: m.Received}}
		days := int(now.Sub(m.Received).Hours() / 24)
		switch {
		case m.Flagged:
			d.Action, d.Why, d.Known = ActionLeave, LeaveFlagged, true
			d.Reason = fmt.Sprintf("%d days old, but flagged - a person is dealing with it", days)
		default:
			d.Action = ActionUnhandled
			d.Reason = fmt.Sprintf("%d days old, past %s, and no lane moved it - to %s for a person to look at",
				days, staleWords(age), folder)
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Received.Before(out[j].Received) })
	return out
}

func staleWords(age time.Duration) string {
	if d := int(age.Hours() / 24); d > 0 {
		return fmt.Sprintf("%d days", d)
	}
	return age.String()
}

// LeftSummary is the leave count by reason - what stayed in the inbox and
// why - and the never-read mail that has been there a while.
type LeftSummary struct {
	ByWhy map[string]int
	// NeverReadOld is how many never-read messages are older than the age
	// asked for: mail the digest should have read days ago. It is the one
	// figure here that means "the fleet missed something".
	NeverReadOld int
	// Oldest is the age of the oldest never-read message, zero when none.
	Oldest time.Duration
}

// Left summarises the leaves in a plan.
func Left(plan []Decision, now time.Time, neverReadAge time.Duration) LeftSummary {
	s := LeftSummary{ByWhy: map[string]int{}}
	for _, d := range plan {
		if d.Action != ActionLeave {
			continue
		}
		why := d.Why
		if why == "" {
			why = "other"
		}
		s.ByWhy[why]++
		if why != LeaveNeverRead {
			continue
		}
		age := now.Sub(d.Received)
		if age > s.Oldest {
			s.Oldest = age
		}
		if neverReadAge > 0 && age > neverReadAge {
			s.NeverReadOld++
		}
	}
	return s
}

// Line is the summary as one line, most worrying first: "LEFT: never-read=3
// (2 over 7d, oldest 9d) not-lane-mail=4 owned-grace=6". Stable order, so
// the runner and a person can read it the same way every day.
func (s LeftSummary) Line(neverReadAge time.Duration) string {
	if len(s.ByWhy) == 0 {
		return "LEFT: nothing"
	}
	order := []string{LeaveNeverRead, LeaveQuarantineHeld, LeaveQuarantineUnread, LeaveNotLaneMail,
		LeaveHeld, LeaveOwnedGrace, LeaveOwnReportGrace, LeaveAutoReplyWait, LeaveFlagged}
	seen := map[string]bool{}
	var parts []string
	add := func(k string) {
		n := s.ByWhy[k]
		if n == 0 || seen[k] {
			return
		}
		seen[k] = true
		p := fmt.Sprintf("%s=%d", k, n)
		if k == LeaveNeverRead {
			p += fmt.Sprintf(" (%d over %s, oldest %s)", s.NeverReadOld, staleWordsShort(neverReadAge),
				staleWordsShort(s.Oldest))
		}
		parts = append(parts, p)
	}
	for _, k := range order {
		add(k)
	}
	var rest []string
	for k := range s.ByWhy {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	return "LEFT: " + strings.Join(parts, " ")
}

func staleWordsShort(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
