package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// WHAT A RUN WILL DO TO AN EXISTING TICKET, DECIDED IN ONE PLACE.
//
// updateExisting acts on this and a dry run prints it. They used to be
// separate: the dry run said "would be re-checked - 340 host(s) now" and
// nothing about whether IT would hear about it, so the one question a preview
// exists to answer - is anybody getting a comment tomorrow? - was left to the
// reader to work out from host counts. A preview that re-implemented the
// decision would be worse than none the first time the two disagreed, so
// both call planUpdate and nothing else decides.

type updateKind int

const (
	// planClosedNoted: closed, still detected, and already said so once.
	planClosedNoted updateKind = iota
	// planClosedComment: closed, still detected, first time - say it once.
	planClosedComment
	// planRecordOnly: no material change; state is refreshed, no comment.
	planRecordOnly
	// planComment: material drift - spread, a new QID, or reaching zero.
	planComment
)

type updatePlan struct {
	kind  updateKind
	drift jira.Drift
	// notedAt is when closed-but-detected was last said, for planClosedNoted.
	notedAt time.Time
}

// planUpdate decides, from the stored state and the scanner's answer, what
// updateExisting is about to do. Pure: no Jira, no scanner.
func planUpdate(issue jira.Issue, prev *jira.ExposureState, f jira.Finding, now time.Time) updatePlan {
	// A CLOSED ticket with live detections is a human question, not an
	// automation one. Somebody closed it deliberately - exception,
	// compensating control, a replacement ticket - and software that reverses
	// that every night is software that gets switched off. Say it once.
	if issue.IsDone() && f.Count() > 0 {
		if prev != nil && !prev.ClosedButDetectedAt.IsZero() {
			return updatePlan{kind: planClosedNoted, notedAt: prev.ClosedButDetectedAt}
		}
		return updatePlan{kind: planClosedComment}
	}
	d := jira.DiffExposure(prev, f, now)
	if !d.Material() {
		return updatePlan{kind: planRecordOnly, drift: d}
	}
	return updatePlan{kind: planComment, drift: d}
}

// describe says what the plan means for the people on the ticket, in the
// words a preview needs: whether there will be a comment, and why.
func (p updatePlan) describe(f jira.Finding) string {
	d := p.drift
	switch p.kind {
	case planClosedNoted:
		return fmt.Sprintf("closed, still detected on %d host(s) - already noted on %s, no comment",
			f.Count(), p.notedAt.Format("2006-01-02"))
	case planClosedComment:
		return fmt.Sprintf("WOULD COMMENT ONCE: closed, but the scanner still sees it on %d host(s)",
			f.Count())
	case planRecordOnly:
		if d.FirstLook {
			return fmt.Sprintf("no stored state yet - would record %d host(s), no comment",
				f.Count())
		}
		if d.CountAfter < d.CountBefore {
			return fmt.Sprintf("shrank %d -> %d host(s) - recorded, no comment", d.CountBefore, d.CountAfter)
		}
		return fmt.Sprintf("no change (%d host(s)) - no comment", d.CountAfter)
	}
	if d.Resolved {
		return fmt.Sprintf("WOULD COMMENT: no detections remain (was %d) - this ticket can be closed",
			d.CountBefore)
	}
	// "Grew" only when the count did. A new QID on the same machines, or one
	// machine swapped for another, is material without being growth, and
	// "grew 1 -> 1" would be read as a mistake.
	var parts []string
	switch {
	case d.CountAfter > d.CountBefore:
		p := fmt.Sprintf("grew %d -> %d host(s)", d.CountBefore, d.CountAfter)
		if n := len(d.NewHosts); n > 0 {
			p += fmt.Sprintf(", %d new host(s)", n)
		}
		parts = append(parts, p)
	case len(d.NewHosts) > 0:
		parts = append(parts, fmt.Sprintf("%d new host(s), %d -> %d overall",
			len(d.NewHosts), d.CountBefore, d.CountAfter))
	}
	if n := len(d.NewQIDs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new QID(s) on %d host(s)", n, d.CountAfter))
	}
	return "WOULD COMMENT: " + strings.Join(parts, ", ")
}

// storedState reads a ticket's exposure property. A malformed or unreadable
// one is reported and treated as absent: it costs one comparison and must not
// kill the run.
func storedState(ctx context.Context, c *jira.Client, key string) (*jira.ExposureState, bool) {
	var prev jira.ExposureState
	found, err := c.GetProperty(ctx, key, jira.PropertyKey, &prev)
	if err != nil {
		logf("WARNING: %s", safelog.Line(err.Error()))
	}
	if !found {
		return nil, false
	}
	return &prev, true
}

// previewUpdate is the dry run's half: read the stored state, decide, say.
// Reads only - the property GET is the one Jira call it makes.
func previewUpdate(ctx context.Context, c *jira.Client, issue jira.Issue,
	f jira.Finding, now time.Time) string {
	prev, _ := storedState(ctx, c, issue.Key)
	return planUpdate(issue, prev, f, now).describe(f)
}
