package vmscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Invented titles; shaped like the scheduled scan list.
const scheduleXML = `<?xml version="1.0" encoding="UTF-8" ?>
<SCHEDULE_SCAN_LIST_OUTPUT><RESPONSE><DATETIME>2026-11-16T13:00:00Z</DATETIME><SCHEDULE_SCAN_LIST>
<SCAN><ID>1</ID><ACTIVE>1</ACTIVE><TITLE><![CDATA[Main Weekly]]></TITLE>
<SCHEDULE><WEEKLY frequency_weeks="1" weekdays="4" /><START_DATE_UTC>2024-01-04T13:00:00</START_DATE_UTC></SCHEDULE>
<NEXTLAUNCH_UTC>2026-11-19T13:00:00</NEXTLAUNCH_UTC></SCAN>
<SCAN><ID>2</ID><ACTIVE>1</ACTIVE><TITLE><![CDATA[Regional Weekly]]></TITLE>
<SCHEDULE><WEEKLY frequency_weeks="1" weekdays="4" /><START_DATE_UTC>2024-01-04T13:00:00</START_DATE_UTC></SCHEDULE>
<NEXTLAUNCH_UTC>2026-11-19T13:00:00Z</NEXTLAUNCH_UTC></SCAN>
<SCAN><ID>3</ID><ACTIVE>1</ACTIVE><TITLE><![CDATA[Fortnightly]]></TITLE>
<SCHEDULE><WEEKLY frequency_weeks="2" weekdays="2" /></SCHEDULE>
<NEXTLAUNCH_UTC>2026-11-17T13:00:00</NEXTLAUNCH_UTC></SCAN>
<SCAN><ID>4</ID><ACTIVE>1</ACTIVE><TITLE><![CDATA[Monthly Servers]]></TITLE>
<SCHEDULE><MONTHLY day_of_month="1" frequency_months="1" /></SCHEDULE></SCAN>
<SCAN><ID>5</ID><ACTIVE>0</ACTIVE><TITLE><![CDATA[` + "\ufeff" + `Old  Site Weekly]]></TITLE>
<SCHEDULE><WEEKLY frequency_weeks="1" weekdays="1" /></SCHEDULE></SCAN>
<SCAN><ID>6</ID><ACTIVE>1</ACTIVE><TITLE><![CDATA[Brand New]]></TITLE>
<SCHEDULE><WEEKLY frequency_weeks="1" weekdays="5" /><START_DATE_UTC>2026-11-13T13:00:00</START_DATE_UTC></SCHEDULE>
<NEXTLAUNCH_UTC>2026-11-20T13:00:00</NEXTLAUNCH_UTC></SCAN>
</SCHEDULE_SCAN_LIST></RESPONSE></SCHEDULE_SCAN_LIST_OUTPUT>`

// The Monday report: the window is the week before.
var (
	schedNow   = time.Date(2026, 11, 16, 13, 0, 0, 0, time.UTC)
	schedSince = schedNow.Add(-7 * 24 * time.Hour)
)

func TestParseSchedules(t *testing.T) {
	s, err := ParseSchedules([]byte(scheduleXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 6 {
		t.Fatalf("got %d schedules", len(s))
	}
	if s[0].Title != "Main Weekly" || !s[0].Active || s[0].Interval != 7*24*time.Hour ||
		!s[0].Next.Equal(time.Date(2026, 11, 19, 13, 0, 0, 0, time.UTC)) {
		t.Errorf("weekly: %+v", s[0])
	}
	if s[2].Interval != 14*24*time.Hour || s[3].Interval != 0 {
		t.Errorf("fortnightly %v, monthly %v", s[2].Interval, s[3].Interval)
	}
	if s[4].Active || s[4].Title != "Old Site Weekly" {
		t.Errorf("inactive, cleaned title: %+v", s[4])
	}
}

func TestDueTitlesJudgesOnlyWhatItCan(t *testing.T) {
	s, _ := ParseSchedules([]byte(scheduleXML))
	due, notJudged := DueTitles(s, schedSince, schedNow)
	// The two weeklies launched on 11-12. The fortnightly's last launch was
	// 11-03, outside the window. Monthly: no fixed interval, not judged.
	// Brand New began 11-13, after the window opened. The inactive one is
	// not expected.
	if strings.Join(due, "|") != "Main Weekly|Regional Weekly" || notJudged != 1 {
		t.Errorf("due %q, not judged %d", due, notJudged)
	}
	if in := Inactive(s); len(in) != 1 || in[0] != "Old Site Weekly" {
		t.Errorf("inactive %q", in)
	}
}

func TestADueScheduleThatLaunchedNothingIsMissing(t *testing.T) {
	s, _ := ParseSchedules([]byte(scheduleXML))
	due, _ := DueTitles(s, schedSince, schedNow)
	launched := []Scan{{Title: "Main Weekly", LaunchType: "Scheduled", Status: "Finished", FromList: true,
		Ref: "scan/1", Start: schedNow.Add(-4 * 24 * time.Hour), TargetGroups: []string{"A"}}}
	w := Combine(launched, due)
	w.FromSchedules = true
	w.Inactive = Inactive(s)
	w.NotJudged = 1
	if len(w.Missing) != 1 || w.Missing[0] != "Regional Weekly" {
		t.Fatalf("missing %v", w.Missing)
	}
	if !strings.HasPrefix(w.Subject("Acme", schedNow), "[NO RESULT]") {
		t.Errorf("subject %q", w.Subject("Acme", schedNow))
	}
	txt := w.Text("Acme", schedNow)
	for _, want := range []string{"should have run this week and Qualys shows no scan for them: Regional Weekly",
		"switched off in Qualys, so not expected: Old Site Weekly", "1 active schedule(s) have no fixed interval"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q:\n%s", want, txt)
		}
	}
	if !strings.Contains(w.HTML("Acme", schedNow), "launched no scan in the window") {
		t.Error("the HTML card must say the schedule launched nothing")
	}
}

func TestWithoutTheSchedulesTheReportSaysSo(t *testing.T) {
	w := Combine([]Scan{{Title: "Main Weekly", LaunchType: "Scheduled", Status: "Finished"}}, nil)
	w.SchedulesUnavailable = "HTTP 403"
	if txt := w.Text("Acme", schedNow); !strings.Contains(txt, "scan schedules could not be read (HTTP 403)") {
		t.Errorf("text:\n%s", txt)
	}
}

func TestFetchSchedulesListsEverySchedule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/2.0/fo/schedule/scan/" || q.Get("action") != "list" || q.Has("active") {
			t.Errorf("unexpected request %s (an inactive schedule must be listed too)", r.URL)
		}
		_, _ = w.Write([]byte(scheduleXML))
	}))
	defer srv.Close()
	s, err := FetchSchedules(context.Background(), srv.URL, "u", "p")
	if err != nil || len(s) != 6 {
		t.Fatalf("%d schedules, err %v", len(s), err)
	}
}

func TestATruncatedScheduleListIsAnError(t *testing.T) {
	bad := strings.Replace(scheduleXML, "</SCHEDULE_SCAN_LIST>",
		"</SCHEDULE_SCAN_LIST><WARNING><TEXT>limit exceeded</TEXT></WARNING>", 1)
	if _, err := ParseSchedules([]byte(bad)); err == nil {
		t.Error("a truncated schedule list must be refused")
	}
}
