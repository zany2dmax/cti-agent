package vmscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// # WHICH SCANS SHOULD HAVE RUN COMES FROM QUALYS'S SCHEDULES
//
// The scan list says what launched. A schedule that silently stops launching
// (disabled, deleted, failing to start) is simply absent from it, so the
// report would show one scan fewer and say nothing. Qualys's list of scan
// schedules says what SHOULD have run: every active schedule whose last
// launch fell in the window is expected, by its real title, and one with no
// launched scan is reported as missing. The operator no longer keeps a list of
// titles in step with Qualys (VMSCAN_SCANS is now only an addition).
//
// What is judged: an active schedule whose previous launch - its next launch
// minus its interval - is inside the window, and, when Qualys gives no next
// launch, any active daily or weekly schedule. A monthly schedule (no fixed
// interval), one that starts after the window begins, and one whose recurrence
// cannot be read are left out rather than guessed: a false "missing" every
// week is a line people learn to skip.

// Schedule is one scheduled VM scan.
type Schedule struct {
	ID     string
	Title  string
	Active bool
	// Interval is how often it launches; zero when it cannot be read or has
	// no fixed interval (monthly).
	Interval time.Duration
	Start    time.Time // first launch, when Qualys gives it
	Next     time.Time // next launch, when Qualys gives it
}

type xmlScheduleList struct {
	XMLName xml.Name `xml:"SCHEDULE_SCAN_LIST_OUTPUT"`
	Scans   []struct {
		ID       string `xml:"ID"`
		Active   string `xml:"ACTIVE"`
		Title    string `xml:"TITLE"`
		Schedule struct {
			Daily *struct {
				Days string `xml:"frequency_days,attr"`
			} `xml:"DAILY"`
			Weekly *struct {
				Weeks string `xml:"frequency_weeks,attr"`
			} `xml:"WEEKLY"`
			Monthly *struct{} `xml:"MONTHLY"`
			Start   string    `xml:"START_DATE_UTC"`
		} `xml:"SCHEDULE"`
		Next string `xml:"NEXTLAUNCH_UTC"`
	} `xml:"RESPONSE>SCHEDULE_SCAN_LIST>SCAN"`
	Warning string `xml:"RESPONSE>WARNING>TEXT"`
	Error   string `xml:"RESPONSE>TEXT"`
	Code    string `xml:"RESPONSE>CODE"`
}

// ParseSchedules reads the scheduled scan list API's XML. A truncated list is
// an error, as with the scan list.
func ParseSchedules(body []byte) ([]Schedule, error) {
	var x xmlScheduleList
	if err := xml.Unmarshal(body, &x); err != nil {
		return nil, fmt.Errorf("the scan schedule list did not parse: %w", err)
	}
	if x.Code != "" || x.Error != "" {
		return nil, fmt.Errorf("qualys refused the scan schedule list (%s): %s", x.Code, strings.TrimSpace(x.Error))
	}
	if strings.TrimSpace(x.Warning) != "" {
		return nil, fmt.Errorf("qualys truncated the scan schedule list (%s) - refusing to use a partial list",
			strings.TrimSpace(x.Warning))
	}
	var out []Schedule
	for _, s := range x.Scans {
		sc := Schedule{ID: strings.TrimSpace(s.ID), Title: cleanName(s.Title),
			Active: strings.TrimSpace(s.Active) == "1",
			Start:  qualysTime(s.Schedule.Start), Next: qualysTime(s.Next)}
		switch {
		case s.Schedule.Daily != nil:
			sc.Interval = time.Duration(count(s.Schedule.Daily.Days)) * 24 * time.Hour
		case s.Schedule.Weekly != nil:
			sc.Interval = time.Duration(count(s.Schedule.Weekly.Weeks)) * 7 * 24 * time.Hour
		}
		out = append(out, sc)
	}
	return out, nil
}

// count reads a frequency attribute; missing or unreadable is 1 only when the
// element itself was present (Qualys omits the attribute for "every").
func count(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// qualysTime reads the API's UTC times, with or without a zone suffix.
func qualysTime(v string) time.Time {
	v = strings.TrimSpace(v)
	for _, f := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(f, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// Due reports whether the schedule should have launched in [since, now), and
// whether that could be judged at all.
func (s Schedule) Due(since, now time.Time) (due, judged bool) {
	if !s.Active {
		return false, true
	}
	if !s.Start.IsZero() && s.Start.After(since) {
		return false, true // new since the window began
	}
	if s.Interval <= 0 {
		return false, false
	}
	if !s.Next.IsZero() {
		last := s.Next.Add(-s.Interval)
		return !last.Before(since) && last.Before(now), true
	}
	// No next launch: a weekly or more frequent schedule always has one in a
	// week's window.
	if s.Interval <= 7*24*time.Hour && now.Sub(since) >= s.Interval {
		return true, true
	}
	return false, false
}

// DueTitles is the titles of the schedules due in the window, and how many
// active schedules could not be judged.
func DueTitles(schedules []Schedule, since, now time.Time) (titles []string, notJudged int) {
	seen := map[string]bool{}
	for _, s := range schedules {
		if !s.Active {
			continue
		}
		due, judged := s.Due(since, now)
		if !judged {
			notJudged++
			continue
		}
		if due && !seen[norm(s.Title)] {
			seen[norm(s.Title)] = true
			titles = append(titles, s.Title)
		}
	}
	return titles, notJudged
}

// Inactive is the titles of the schedules switched off in Qualys.
func Inactive(schedules []Schedule) []string {
	var out []string
	for _, s := range schedules {
		if !s.Active {
			out = append(out, s.Title)
		}
	}
	return out
}

// FetchSchedules lists every VM scan schedule, active or not: one switched
// off is worth saying, and it is not "missing". Read-only.
func FetchSchedules(ctx context.Context, baseURL, username, password string) ([]Schedule, error) {
	q := url.Values{}
	q.Set("action", "list")
	body, err := qualysGet(ctx, baseURL, username, password, "/api/2.0/fo/schedule/scan/", q, "scan schedule list")
	if err != nil {
		return nil, err
	}
	return ParseSchedules(body)
}
