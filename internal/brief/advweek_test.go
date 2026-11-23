package brief

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// weekFixture writes daily triage reports into a state folder: yesterday's
// with a likely verdict, one mid-week with a sighting, one with only an
// unlikely verdict, and two outside the window - eight days back, and today
// (the window ends yesterday: today's daily may still be running).
func weekFixture(t *testing.T) (string, time.Time) {
	d := t.TempDir()
	now := time.Date(2026, 11, 23, 7, 0, 0, 0, time.UTC)
	rep := func(day, results string, cost string) {
		writeFile(t, filepath.Join(d, "enriched-"+day+"-advisories.json"),
			`{"schema": "cti-advisories/1", "read": 2, "cost_usd": `+cost+`, "gaps": ["no Discover"], "results": [`+results+`]}`)
	}
	rep("2026-11-23", `{"subject": "Today, not yet", "sender": "t@x.example",
	   "verdicts": {"sightings": [{"value": "today.example", "type": "domain", "hosts_seen_on": 1}], "verdicts": []}}`, "5")
	rep("2026-11-22", `{"subject": "Sunday likely", "sender": "a@x.example",
	   "verdicts": {"sightings": [], "verdicts": [{"title": "Widget", "relevance": "likely", "reason": "on 3 hosts"}]}},
	  {"subject": "Re: lunch", "sender": "b@x.example", "not_threat_intel": true}`, "0.05")
	rep("2026-11-19", `{"subject": "<b>Wed</b> campaign", "sender": "c@x.example",
	   "verdicts": {"sightings": [{"value": "evil.example", "type": "domain", "hosts_seen_on": 2}],
	                "verdicts": [{"title": "Campaign", "relevance": "unknown", "reason": "-"}]}},
	  {"subject": "Over the cap", "sender": "d@x.example", "not_triaged": "over the cap"}`, "0.04")
	rep("2026-11-18", `{"subject": "Quiet one", "sender": "e@x.example",
	   "verdicts": {"sightings": [], "verdicts": [{"title": "7-Zip", "relevance": "unlikely", "reason": "not installed"}]}},
	  {"subject": "Only CVEs", "sender": "g@x.example", "cve_items": ["X (CVE-2026-9)"],
	   "verdicts": {"sightings": [], "verdicts": []}}`, "0.01")
	rep("2026-11-15", `{"subject": "Last week", "sender": "f@x.example",
	   "verdicts": {"sightings": [{"value": "old.example", "type": "domain", "hosts_seen_on": 1}], "verdicts": []}}`, "9")
	return d, now
}

func weekData(t *testing.T, enabled bool) obj {
	d, now := weekFixture(t)
	data := obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now"}
	Prepare(data, filepath.Join(d, "weekly-enriched-2026-11-23.json"), "weekly", enabled, now)
	return data
}

// The weekly rolls up the week's dailies: sightings first, then likely and
// possible, each with its day; the rest as one count line; nothing from
// outside the window.
func TestTheWeeklyRollsUpTheWeeksAdvisories(t *testing.T) {
	data := weekData(t, true)
	txt := strings.Join(advisoriesText(data), "\n")
	mustContain(t, txt, "FLEET ADVISORIES - 6 threat-intel messages this week, 2 worth a look")
	mustContain(t, txt, "Rolled up from 3 daily triage reports (2026-11-18, 2026-11-19, 2026-11-22). No model was run")
	a, b := strings.Index(txt, "SEEN ON OUR HOSTS: evil.example"), strings.Index(txt, "LIKELY  Widget")
	if a < 0 || b < 0 || a > b {
		t.Errorf("the sighting (%d) is not before the likely verdict (%d):\n%s", a, b, txt)
	}
	mustContain(t, txt, "    2026-11-19 - from c@x.example")
	mustContain(t, txt, "    2026-11-22 - from a@x.example")
	mustNotContain(t, txt, "today.example")
	mustNotContain(t, txt, "Quiet one")
	mustNotContain(t, txt, "Last week")
	mustNotContain(t, txt, "old.example")
	mustContain(t, txt, "The rest: 1 judged unlikely or unknown, 2 not triaged or with no verdict, 1 read with no threat found.")
	mustContain(t, txt, "No triage report for: 2026-11-16, 2026-11-17, 2026-11-20, 2026-11-21.")
	mustContain(t, txt, "Not covered: no Discover.")
	mustContain(t, txt, "Model cost this week, in the dailies: $0.10.")

	html := render(data, "weekly")
	mustContain(t, html, "FLEET ADVISORIES &mdash; 6 threat-intel messages this week, 2 worth a look")
	mustContain(t, html, "2026-11-19 &middot; from c@x.example")
	mustContain(t, html, "&lt;b&gt;Wed&lt;/b&gt; campaign")
	mustNotContain(t, html, "<b>Wed</b>")
	mustNotContain(t, html, "href")
}

// --advisories-dir and --week-days: a dry run's enriched file is not in the
// state folder, and WEEKLY_DAYS can widen the window.
func TestSetWeekAdvisoriesTakesAFolderAndAWindow(t *testing.T) {
	d, now := weekFixture(t)
	data := obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now"}
	Prepare(data, filepath.Join(t.TempDir(), "weekly-enriched-2026-11-23.json"), "weekly", true, now)
	mustContain(t, strings.Join(advisoriesText(data), "\n"), "no daily triage report was found for the last 7 days")
	SetWeekAdvisories(data, d, now, 9)
	txt := strings.Join(advisoriesText(data), "\n")
	mustContain(t, txt, "SEEN ON OUR HOSTS: old.example")
	mustContain(t, txt, "Rolled up from 4 daily triage reports (2026-11-15, ")
	mustNotContain(t, txt, "today.example")
}

// A week with nothing worth a look says so.
func TestAQuietWeekSaysSo(t *testing.T) {
	d := t.TempDir()
	now := time.Date(2026, 11, 23, 7, 0, 0, 0, time.UTC)
	writeFile(t, filepath.Join(d, "enriched-2026-11-20-advisories.json"),
		`{"schema": "cti-advisories/1", "read": 1, "results": [{"subject": "Q", "sender": "q@x.example",
		  "verdicts": {"sightings": [], "verdicts": [{"title": "T", "relevance": "unlikely"}]}}]}`)
	data := obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now"}
	Prepare(data, filepath.Join(d, "weekly-enriched-2026-11-23.json"), "weekly", false, now)
	txt := strings.Join(advisoriesText(data), "\n")
	mustContain(t, txt, "Nothing this week was seen on our hosts or judged likely or possible.")
	mustNotContain(t, txt, "No triage report for")
}

// No reports: a line when triage is on, nothing when it is off.
func TestAWeekWithNoReports(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		data := obj{"findings": []any{}, "counts": obj{}, "total": json0, "generated": "now"}
		Prepare(data, filepath.Join(t.TempDir(), "weekly-enriched-2026-11-23.json"), "weekly", enabled,
			time.Date(2026, 11, 23, 7, 0, 0, 0, time.UTC))
		got := advisoriesSection(data)
		if enabled {
			mustContain(t, got, "no daily triage report was found for the last 7 days")
		} else if got != "" || len(advisoriesText(data)) != 0 {
			t.Errorf("triage off, no reports: %q", got)
		}
	}
}

// The daily is unchanged by the roll-up: no day on its rows.
func TestTheDailyRowsCarryNoDay(t *testing.T) {
	txt := strings.Join(advisoriesText(advData(t, true, true, "daily")), "\n")
	mustNotContain(t, txt, "Rolled up")
	mustContain(t, txt, "\n    from a@b.example")
}
