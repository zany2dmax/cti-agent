package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// WHICH TEXT DOES THE GATEWAY REFUSE?
//
//	cti-jira --appscan-tickets T.json --appscan-test 1234 --appscan-comment-probe CR-99 [--for-real]
//
// On 2026-10-30 two weekly comments came back "HTTP 403: ERROR: The request
// could not be satisfied" - a firewall's page, not Jira's - while the same text
// had been accepted as a ticket description and attachment. This posts the
// comment the weekly run would post for one application onto a TEST ticket
// (filed by --appscan-test; the label is checked) and, if it is refused,
// bisects it by line until it names the smallest refused pieces. Preview
// unless --for-real; a preview posts nothing.

// probeMaxPosts bounds one probe, so a comment that is refused everywhere
// cannot post hundreds of comments on the test ticket.
const probeMaxPosts = 80

// probePause spaces the posts. A variable so tests do not wait.
var probePause = 400 * time.Millisecond

type commentPoster func(ctx context.Context, key, text string) error

// refusedPiece is a group of lines the gateway refused. Together means each
// half was accepted alone: the refusal needs the whole group (size, or a
// combination of lines).
type refusedPiece struct {
	First, Last int // 1-based line numbers
	Lines       []string
	Together    bool
	Unresolved  bool // the post budget ran out before this was narrowed
}

type probe struct {
	post   commentPoster
	key    string
	posted int
	last   error // the most recent refusal, for the report
}

func (p *probe) try(ctx context.Context, lines []string) (refused bool, exhausted bool) {
	if strings.TrimSpace(strings.Join(lines, "")) == "" {
		return false, false // nothing to refuse, and Jira rejects an empty comment
	}
	if p.posted >= probeMaxPosts {
		return false, true
	}
	p.posted++
	time.Sleep(probePause)
	err := p.post(ctx, p.key, fmt.Sprintf("[comment probe %d] ", p.posted)+strings.Join(lines, "\n"))
	if err != nil {
		p.last = err
		return true, false
	}
	return false, false
}

// bisect narrows a chunk already known to be refused. off is the index of
// lines[0] in the whole comment.
func (p *probe) bisect(ctx context.Context, lines []string, off int) []refusedPiece {
	if len(lines) == 1 {
		return []refusedPiece{{First: off + 1, Last: off + 1, Lines: lines}}
	}
	mid := len(lines) / 2
	halves := [2]struct {
		lines []string
		off   int
	}{{lines[:mid], off}, {lines[mid:], off + mid}}
	var out []refusedPiece
	found := false
	for _, h := range halves {
		refused, exhausted := p.try(ctx, h.lines)
		if exhausted {
			return []refusedPiece{{First: off + 1, Last: off + len(lines), Lines: lines, Unresolved: true}}
		}
		if refused {
			found = true
			out = append(out, p.bisect(ctx, h.lines, h.off)...)
		}
	}
	if !found {
		return []refusedPiece{{First: off + 1, Last: off + len(lines), Lines: lines, Together: true}}
	}
	return out
}

// runProbe returns what happened in words, and the refused pieces if any.
func (p *probe) run(ctx context.Context, text string) (verdict string, pieces []refusedPiece) {
	if refused, _ := p.try(ctx, []string{"control: a plain sentence"}); refused {
		return "a plain one-line comment was refused too: the gateway or the account blocks comments " +
			"on this ticket whatever they say - not a text problem", nil
	}
	lines := strings.Split(text, "\n")
	refused, exhausted := p.try(ctx, lines)
	if exhausted {
		return "post budget exhausted", nil
	}
	if !refused {
		return "the whole comment was ACCEPTED: this text is not what the gateway refuses (the refusal " +
			"on 2026-10-30 did not reproduce - it may have been transient, or depended on that week's diff)", nil
	}
	return "the whole comment was refused; narrowed by line:", p.bisect(ctx, lines, 0)
}

// openTestTicket confirms key is an open ticket filed by --appscan-test: the
// probe comments on nothing else.
func openTestTicket(ctx context.Context, c *jira.Client, cfg config.Config, key string) error {
	jql := fmt.Sprintf(`project = %q AND key = %q AND labels = %q AND statusCategory != Done`,
		cfg.JiraProjectKey, key, appscanTestLabel)
	hits, err := c.Search(ctx, jql, 2)
	if err != nil {
		return fmt.Errorf("searching for %s failed: %w", safelog.Line(key), err)
	}
	if len(hits) != 1 || hits[0].Key != key {
		return fmt.Errorf("%s is not an open ticket in project %s labelled %s - the probe comments only on "+
			"tickets filed by --appscan-test", safelog.Line(key), safelog.Line(cfg.JiraProjectKey), appscanTestLabel)
	}
	for _, l := range hits[0].Fields.Labels {
		if l == appscanLabel {
			return fmt.Errorf("%s is one of the weekly run's tickets; the probe will not comment on it", safelog.Line(key))
		}
	}
	return nil
}

func doAppscanCommentProbe(ctx context.Context, c *jira.Client, cfg config.Config,
	path, appID, key string, forReal bool, now time.Time) int {

	t, err := testTicketFor(path, appID)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	// The comment of a week in which everything is new: the largest the weekly
	// run would post for this application, and it contains every finding.
	text := appscanComment(t, appscanState{}, now)
	lines := strings.Split(text, "\n")
	if !forReal {
		fmt.Printf("===== would post this comment to %s (%d lines, %d characters), and bisect it if refused\n",
			safelog.Line(key), len(lines), len(text))
		logf("appscan-comment-probe: DRY RUN - nothing posted. Add --for-real (at most %d comments on %s).",
			probeMaxPosts, safelog.Line(key))
		return exitOK
	}
	if err := jira.CheckAllowed(cfg.JiraProjectKey, cfg.JiraAllowCreate); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	if err := openTestTicket(ctx, c, cfg, key); err != nil {
		return die("%s", err)
	}
	p := &probe{post: c.AddComment, key: key}
	verdict, pieces := p.run(ctx, text)
	logf("appscan-comment-probe: %s (%d comment(s) posted on %s)", verdict, p.posted, safelog.Line(key))
	for _, pc := range pieces {
		how := "refused"
		switch {
		case pc.Unresolved:
			how = "refused, not narrowed further (post budget)"
		case pc.Together:
			how = "refused only as a group - each half alone was accepted"
		}
		rng := fmt.Sprintf("line %d", pc.First)
		if pc.Last != pc.First {
			rng = fmt.Sprintf("lines %d-%d", pc.First, pc.Last)
		}
		fmt.Printf("%s: %s\n", rng, how)
		for i, l := range pc.Lines {
			if i >= 6 {
				fmt.Printf("    ... %d more\n", len(pc.Lines)-i)
				break
			}
			fmt.Printf("    %s\n", oneLine(l, 200))
		}
	}
	if p.last != nil {
		logf("appscan-comment-probe: last refusal: %s", safelog.Line(p.last.Error()))
	}
	if len(pieces) > 0 {
		return exitFailure
	}
	return exitOK
}
