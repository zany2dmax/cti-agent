// Package patchtuesday assembles the monthly Microsoft Patch Tuesday
// synopsis: two public wrap-ups, correlated against what the scanner actually
// finds in this environment, rendered as one email.
//
// # WHY THIS IS ITS OWN LANE
//
// It looks like the scout lane but is not. @scout polls feeds continuously for
// CVE IDs and dedupes them; it has no notion of a monthly anchor, cannot pull
// a QQL query string out of prose, and produces findings rather than an
// article. This lane adds a different axis: the *vendor release cycle*. Once a
// month Microsoft ships a defined set of fixes, and the question is not "what
// is new today" but "what did this release land on us, and what do we tell the
// patching team".
//
// What it reuses rather than reinventing: the Qualys KnowledgeBase cache for
// CVE-to-QID mapping, Host Detection for presence, enrich.py for severity
// banding, and mailer.py as the single outbound channel. Presence still comes
// only from the scanner.
package patchtuesday

import (
	"fmt"
	"time"
)

// PatchTuesday returns the second Tuesday of the given month.
func PatchTuesday(year int, month time.Month) time.Time {
	first := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	// Weekday() has Sunday=0; Tuesday=2. Walk forward to the first Tuesday,
	// then add a week.
	offset := (int(time.Tuesday) - int(first.Weekday()) + 7) % 7
	return first.AddDate(0, 0, offset+7)
}

// ReportDay is the morning the synopsis goes out: the Wednesday immediately
// after Patch Tuesday.
//
// NOT "the second Wednesday of the month", which is what this is usually
// called and is wrong in roughly one month in seven. Whenever the 1st falls on
// a Wednesday, the second Wednesday lands SIX DAYS BEFORE Patch Tuesday -
// April and July 2026, September and December 2027, and so on. A lane
// scheduled on the second Wednesday would wake up before the content it is
// meant to summarise exists, find nothing, and report an empty month.
//
// The Wednesday after the second Tuesday is always Patch Tuesday + 1, and
// always falls between the 9th and the 15th, which is what the systemd timer
// encodes.
func ReportDay(year int, month time.Month) time.Time {
	return PatchTuesday(year, month).AddDate(0, 0, 1)
}

// TargetMonth picks the month to report on, given the day the lane is running.
//
// On or after this month's Patch Tuesday, report on this month. Before it,
// the newest release is still last month's - which is what makes a run on the
// 1st of the month do something sensible instead of reporting on a Patch
// Tuesday that has not happened.
func TargetMonth(now time.Time) (int, time.Month) {
	y, m := now.Year(), now.Month()
	if now.Before(PatchTuesday(y, m)) {
		prev := time.Date(y, m, 1, 0, 0, 0, 0, now.Location()).AddDate(0, 0, -1)
		return prev.Year(), prev.Month()
	}
	return y, m
}

// ParseMonth accepts "2026-09" for replaying a past month.
func ParseMonth(s string) (int, time.Month, error) {
	t, err := time.Parse("2006-01", s)
	if err != nil {
		return 0, 0, fmt.Errorf("month must be YYYY-MM (e.g. 2026-09), got %q", s)
	}
	return t.Year(), t.Month(), nil
}

// Released reports whether the given month's Patch Tuesday has actually
// happened yet. Guard against an over-eager run: summarising a release that
// does not exist produces a confidently empty email, which is worse than no
// email because it looks like a quiet month.
func Released(year int, month time.Month, now time.Time) bool {
	return !now.Before(PatchTuesday(year, month))
}

// MonthLabel is "September 2026", as used in the subject line.
func MonthLabel(year int, month time.Month) string {
	return fmt.Sprintf("%s %d", month.String(), year)
}
