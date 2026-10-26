package main

import (
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/jira"
)

func issue(key, summary string, labels ...string) jira.Issue {
	var is jira.Issue
	is.Key = key
	is.Fields.Summary = summary
	is.Fields.Labels = labels
	return is
}

func app(key, id string) jira.Issue {
	return issue(key, "AppSec: app "+id, "cti-agent", "cti-appscan", "cti-appscan-"+id)
}

func TestAppIDFromLabels(t *testing.T) {
	cases := []struct {
		labels []string
		id     string
		ok     bool
	}{
		{[]string{"cti-agent", "cti-appscan", "cti-appscan-1205213703"}, "1205213703", true},
		{[]string{"cti-appscan"}, "", false},
		{[]string{"cti-appscan-some-name-a1b2c3"}, "", false}, // name-keyed: never judged
		{[]string{"cti-appscan-12x4"}, "", false},
		{[]string{"cti-appscan-"}, "", false},
		{nil, "", false},
	}
	for _, c := range cases {
		id, ok := appIDFromLabels(c.labels)
		if id != c.id || ok != c.ok {
			t.Errorf("%v -> (%q,%v), want (%q,%v)", c.labels, id, ok, c.id, c.ok)
		}
	}
}

func TestPlanRetireClosesOnlyApplicationsMissingFromTheList(t *testing.T) {
	open := []jira.Issue{
		app("CR-1", "101"),
		app("CR-2", "202"),
		app("CR-4", "404"),
		issue("CR-3", "AppSec: by name", "cti-appscan", "cti-appscan-by-name-ab12cd"),
	}
	got, why := planRetire(open, []string{"101", "303", "404"}, []string{"101"}, nil)
	if why != "" || len(got) != 1 || got[0].Issue.Key != "CR-2" || got[0].AppID != "202" {
		t.Fatalf("got %+v, %q", got, why)
	}
}

func TestPlanRetireClosesNothingWithoutAScannerList(t *testing.T) {
	open := []jira.Issue{app("CR-2", "202")}
	for _, list := range [][]string{nil, {}} {
		got, why := planRetire(open, list, nil, nil)
		if len(got) != 0 || why == "" {
			t.Fatalf("an absent list must close nothing and say why: %+v %q", got, why)
		}
	}
}

func TestPlanRetireRefusesAListThatDisagreesWithThisWeeksScans(t *testing.T) {
	open := []jira.Issue{app("CR-2", "202"), app("CR-1", "101"), app("CR-5", "505")}
	// 101 was scanned this run but the scanner's list lacks it: the list is
	// wrong, so no ticket is judged retired - not even 202.
	got, why := planRetire(open, []string{"505"}, []string{"101"}, nil)
	if len(got) != 0 || !strings.Contains(why, "cannot be trusted") {
		t.Fatalf("got %+v, %q", got, why)
	}
}

func TestPlanRetireRefusesAMassClosure(t *testing.T) {
	var open []jira.Issue
	for _, id := range []string{"1", "2", "3", "4", "5", "6", "7", "8"} {
		open = append(open, app("CR-"+id, id))
	}
	got, why := planRetire(open, []string{"999"}, nil, nil)
	if len(got) != 0 || !strings.Contains(why, "none was closed") {
		t.Fatalf("more than %d at once must close none: %+v %q", maxRetirePerRun, got, why)
	}
	// Exactly the cap out of a large queue is housekeeping.
	got, why = planRetire(open, []string{"4", "5", "6", "7", "8"}, nil, nil)
	if len(got) != maxRetirePerRun || why != "" {
		t.Fatalf("up to the cap is allowed: %+v %q", got, why)
	}
}

func TestPlanRetireRefusesMostOfASmallQueue(t *testing.T) {
	open := []jira.Issue{app("CR-1", "1"), app("CR-2", "2"), app("CR-3", "3")}
	// Two of three gone at once is the same fault as everything gone.
	if got, why := planRetire(open, []string{"3"}, nil, nil); len(got) != 0 || why == "" {
		t.Fatalf("most of the queue at once must close none: %+v %q", got, why)
	}
	// One of one or one of three is an ordinary retirement.
	if got, _ := planRetire(open[:1], []string{"9"}, nil, nil); len(got) != 1 {
		t.Fatalf("a single retirement is allowed: %+v", got)
	}
	if got, _ := planRetire(open, []string{"2", "3"}, nil, nil); len(got) != 1 {
		t.Fatalf("one of three is allowed: %+v", got)
	}
}

func TestPlanRetireRefusesAFullSearchPage(t *testing.T) {
	open := make([]jira.Issue, retireSearchMax)
	for i := range open {
		open[i] = app("CR-1", "1")
	}
	if got, why := planRetire(open, []string{"2"}, nil, nil); len(got) != 0 || why == "" {
		t.Fatalf("a full page cannot be judged: %+v %q", got, why)
	}
}

func TestPlanRetireNeedsTheSharedLabelAndTheFleetsState(t *testing.T) {
	// Only an app label, not the fleet's shared label: not ours.
	lone := issue("CR-9", "x", "cti-appscan-202")
	if got, _ := planRetire([]jira.Issue{lone, app("CR-1", "1")}, []string{"1"}, nil, nil); len(got) != 0 {
		t.Fatalf("a ticket without the shared label must be left alone: %+v", got)
	}
	// Labelled like ours but without the state property: someone else's.
	open := []jira.Issue{app("CR-2", "202"), app("CR-3", "303"), app("CR-4", "404"), app("CR-5", "505")}
	ours := func(is jira.Issue) bool { return is.Key != "CR-2" }
	got, _ := planRetire(open, []string{"404", "505"}, nil, ours)
	if len(got) != 1 || got[0].Issue.Key != "CR-3" {
		t.Fatalf("a ticket the fleet did not file must be left alone: %+v", got)
	}
}

func TestRetireCommentSaysWhy(t *testing.T) {
	c := retireComment(issue("CR-2", "AppSec: Gone", "cti-appscan-202"), "202",
		time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{"30 October 2026", "202", "AppSec: Gone", "closed automatically", "same web application"} {
		if !strings.Contains(c, want) {
			t.Errorf("comment lacks %q: %s", want, c)
		}
	}
}
