package brief

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── FLEET ADVISORIES, THIS WEEK ─────────────────────────────────────────────
//
// The weekly reads no mail and runs no model, so it has no advisories of its
// own. It rolls up the reports the week's dailies already wrote beside their
// enriched files (enriched-DAY-advisories.json): what was seen on our hosts,
// then what was judged likely or possible, each with its day, then one line
// counting the rest. Until 23 Nov 2026 the weekly had no section at all, so
// a reader of only the Monday brief never saw a Wednesday sighting.

// weekDays is the weekly's window when run-digest does not pass
// WEEKLY_DAYS (cti-brief --week-days).
const weekDays = 7

// advDay is one daily's triage report and the day it is for.
type advDay struct {
	day    string
	report obj
}

// advWeekData is the window - the days up to yesterday, oldest first - and
// the reports for the days that have one.
type advWeekData struct {
	window []string
	days   []advDay
}

// SetWeekAdvisories points the weekly's roll-up at dir (the real state
// folder, even for a dry run, whose enriched file is elsewhere) and a window
// of days. Prepare calls it with the enriched file's folder and weekDays.
func SetWeekAdvisories(data obj, dir string, now time.Time, days int) {
	if days < 1 {
		days = weekDays
	}
	data["_advisories_week"] = loadWeekAdvisories(dir, now, days)
}

// loadWeekAdvisories reads the window's reports. The window ends yesterday:
// today's daily may still be running when the weekly starts (both timers
// catch up after downtime), and consecutive weeklies then cover consecutive
// days with no overlap. A missing or malformed report is skipped, as the
// daily skips it.
func loadWeekAdvisories(dir string, now time.Time, days int) advWeekData {
	var w advWeekData
	for i := days; i >= 1; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		w.window = append(w.window, day)
		if rep, ok := loadAdvisories(filepath.Join(dir, "enriched-"+day+".json")).(obj); ok {
			w.days = append(w.days, advDay{day, rep})
		}
	}
	return w
}

// advWeek is the week's reports gathered for rendering.
type advWeek struct {
	days          []advDay
	worth         []advResult // seen on our hosts, likely or possible
	when          []string    // worth[i]'s day
	read, rest    int         // threat-intel messages read; judged unlikely or unknown
	notTriaged    int         // not triaged, or triaged with no verdict
	windowLen     int
	quiet         int // read, no threat found
	overCap       int
	cost          float64
	gaps, missing []string
	enabled       bool
}

func gatherWeek(data obj) advWeek {
	w := advWeek{enabled: truthy(data["_triage_enabled"])}
	wd, _ := data["_advisories_week"].(advWeekData)
	w.days, w.windowLen = wd.days, len(wd.window)
	type item struct {
		a   advResult
		day string
	}
	var items []item
	have := map[string]bool{}
	seenGap := map[string]bool{}
	for _, d := range w.days {
		have[d.day] = true
		w.read += pyInt(or(d.report["read"], json0))
		w.cost += pyFloat(or(d.report["cost_usd"], json0))
		w.quiet += len(advNotIntel(d.report))
		w.overCap += pyInt(or(d.report["over_ingest_cap"], json0))
		for _, g := range asList(or(d.report["gaps"], []any{})) {
			if s := str(g); s != "" && !seenGap[s] {
				seenGap[s] = true
				w.gaps = append(w.gaps, s)
			}
		}
		for _, a := range advResults(d.report) {
			switch {
			case a.seen == 0 || a.best <= 1:
				items = append(items, item{a, d.day})
			case a.best == 5 || len(a.verdicts) == 0:
				w.notTriaged++
			default:
				w.rest++
			}
		}
	}
	// Sightings first, then likely before possible, then the latest day.
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].a.seen != items[j].a.seen {
			return items[i].a.seen < items[j].a.seen
		}
		if items[i].a.best != items[j].a.best {
			return items[i].a.best < items[j].a.best
		}
		return items[i].day > items[j].day
	})
	for _, it := range items {
		w.worth = append(w.worth, it.a)
		w.when = append(w.when, it.day)
	}
	if w.enabled {
		for _, d := range wd.window {
			if !have[d] {
				w.missing = append(w.missing, d)
			}
		}
	}
	return w
}

func (w advWeek) heading() string {
	return fmt.Sprintf("%d threat-intel message%s this week, %d worth a look",
		w.read, pluralN(w.read), len(w.worth))
}

func (w advWeek) dayList() string {
	ds := make([]string, len(w.days))
	for i, d := range w.days {
		ds[i] = d.day
	}
	return fmt.Sprintf("Rolled up from %d daily triage report%s (%s). No model was run for this summary.",
		len(w.days), pluralN(len(w.days)), strings.Join(ds, ", "))
}

func (w advWeek) restLine() string {
	return fmt.Sprintf("The rest: %d judged unlikely or unknown, %d not triaged or with no verdict, %d read with no threat found. "+
		"Each day's Daily Brief lists them.", w.rest, w.notTriaged, w.quiet)
}

const advWeekNone = "Nothing this week was seen on our hosts or judged likely or possible."

func advWeekEmpty(w advWeek) (string, bool) {
	if len(w.days) > 0 {
		return "", false
	}
	if !w.enabled {
		return "", true
	}
	return fmt.Sprintf("Advisory triage is on but no daily triage report was found for the last %d days. "+
		"The daily digest run logs say why.", w.windowLen), true
}

func advWeekSection(data obj) string {
	w := gatherWeek(data)
	var rows strings.Builder
	note := func(s string) {
		rows.WriteString(`<tr><td style="padding:4px 0;color:#718096">` + htmlEscape(s) + `</td></tr>`)
	}
	summary := "no report"
	if empty, none := advWeekEmpty(w); none {
		if empty == "" {
			return ""
		}
		rows.WriteString(`<tr><td style="padding:4px 0;color:#4a5568">` + htmlEscape(empty) + `</td></tr>`)
	} else {
		summary = w.heading()
		note(w.dayList())
		for i, a := range w.worth {
			rows.WriteString(advRowHTML(a, w.when[i]))
		}
		if len(w.worth) == 0 {
			note(advWeekNone)
		}
		note(w.restLine())
		if w.overCap > 0 {
			note(fmt.Sprintf("+%d more not saved for triage over the week (over the ingest cap).", w.overCap))
		}
		if len(w.missing) > 0 {
			note("No triage report for: " + strings.Join(w.missing, ", ") + ".")
		}
		foot := htmlEscape(advNote)
		if len(w.gaps) > 0 {
			foot += "<br>Not covered: " + htmlEscape(strings.Join(w.gaps, "; ")) + "."
		}
		foot += fmt.Sprintf("<br>Model cost this week, in the dailies: $%.2f.", w.cost)
		rows.WriteString(`<tr><td style="padding:6px 0;color:#718096;font-size:11px">` + foot + `</td></tr>`)
	}
	return `
  <tr><td style="padding:4px 20px 14px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin:12px 0 8px 0;letter-spacing:.5px">
      ` + advHeading + ` &mdash; ` + htmlEscape(summary) + `</div>
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
      ` + rows.String() + `
    </table>
  </td></tr>`
}

func advWeekText(data obj) []string {
	w := gatherWeek(data)
	if empty, none := advWeekEmpty(w); none {
		if empty == "" {
			return nil
		}
		return []string{advHeading + " - no report", rule68, "  " + empty, ""}
	}
	lines := []string{advHeading + " - " + w.heading(), rule68, "  " + w.dayList()}
	for i, a := range w.worth {
		lines = append(lines, advRowText(a, w.when[i])...)
	}
	if len(w.worth) == 0 {
		lines = append(lines, "  "+advWeekNone)
	}
	lines = append(lines, "  "+w.restLine())
	if w.overCap > 0 {
		lines = append(lines, fmt.Sprintf("  +%d more not saved for triage over the week (over the ingest cap).", w.overCap))
	}
	if len(w.missing) > 0 {
		lines = append(lines, "  No triage report for: "+strings.Join(w.missing, ", ")+".")
	}
	lines = append(lines, "  "+advNote)
	if len(w.gaps) > 0 {
		lines = append(lines, "  Not covered: "+strings.Join(w.gaps, "; ")+".")
	}
	lines = append(lines, fmt.Sprintf("  Model cost this week, in the dailies: $%.2f.", w.cost), "")
	return lines
}
