package appscan

import (
	"testing"
	"time"
)

func TestAScheduledNoticeMatchesOnlyTheRunItAnnounced(t *testing.T) {
	launch := time.Date(2026, 11, 8, 1, 27, 0, 0, time.UTC)
	run := ScanResult{ScanTitle: "Example Shop Run #41", Started: launch.Add(84 * time.Second)}

	if !ScheduledFor("Example Shop", launch, run) {
		t.Error("the run that started 84s after the announced launch must match")
	}
	if !ScheduledFor("  example   shop ", launch, run) {
		t.Error("case and spacing in the title should not matter")
	}
	for name, c := range map[string]struct {
		title  string
		launch time.Time
		run    ScanResult
	}{
		"another app":        {"Example Portal", launch, run},
		"a prefix only":      {"Example", launch, run},
		"last week's launch": {"Example Shop", launch.Add(-7 * 24 * time.Hour), run},
		"run started before": {"Example Shop", launch, ScanResult{ScanTitle: run.ScanTitle, Started: launch.Add(-time.Hour)}},
		"no launch time":     {"Example Shop", time.Time{}, run},
		"no title":           {"", launch, run},
		"run has no start":   {"Example Shop", launch, ScanResult{ScanTitle: run.ScanTitle}},
	} {
		if ScheduledFor(c.title, c.launch, c.run) {
			t.Errorf("%s: matched, and the notice would be deleted", name)
		}
	}
}
