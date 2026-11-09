package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/supplier"
)

func twoItems() []supplier.Item {
	mk := func(id, name string) supplier.Item {
		r := supplier.Request{MessageID: id, ConversationID: "conv-" + id, Subject: "New supplier request",
			From: "a@example.test", Received: time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC),
			State: supplier.StateRead, Form: &supplier.Form{Name: name, Notes: "x"}}
		in := supplier.Input{MessageID: id, Sender: r.From, Subject: r.Subject, State: r.State, Form: r.Form, Body: "x"}
		return supplier.Item{Request: r, Input: supplier.Render(in, supplier.Config{}), Source: in.Source()}
	}
	return []supplier.Item{mk("a", "Cloud Backup Inc"), mk("b", "Gravel Co")}
}

func setup(t *testing.T, items []supplier.Item) string {
	t.Helper()
	dir := t.TempDir()
	if err := writeItems(dir, supplier.Collected{Items: items}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"SUPPLIER_JIRA_PROJECT", "SUPPLIER_BOARD_URL", "SUPPLIER_TECH_TERMS", "FLEET_ORG"} {
		t.Setenv(k, "")
	}
	return dir
}

func TestCollectWritesOneInputPerRequestPrivately(t *testing.T) {
	dir := t.TempDir()
	if err := writeItems(dir, supplier.Collected{Items: twoItems()}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"requests.json", "000.input.txt", "001.input.txt"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", name, fi, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "000.input.txt"))
	if !strings.Contains(string(b), "<<<BEGIN UNTRUSTED CONTENT") {
		t.Error("the model's input has no untrusted block")
	}
}

func TestWithNoAddressTheLaneDoesNothing(t *testing.T) {
	t.Setenv("SUPPLIER_ADDRESS", "")
	dir := filepath.Join(t.TempDir(), "w")
	if code := doCollect(dir, 0); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "requests.json"))
	var col collected
	if err := json.Unmarshal(b, &col); err != nil || len(col.Items) != 0 || col.AutomaticSkipped != 0 {
		t.Errorf("requests.json = %s (%v)", b, err)
	}
}

func TestFinishWithNoModelMakesEveryRequestUnsureAndStillWritesTheDigest(t *testing.T) {
	dir := setup(t, twoItems())
	if code := doFinish(dir, false); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	subj, _ := os.ReadFile(filepath.Join(dir, "digest.subject"))
	if !strings.Contains(string(subj), "0 critical, 2 unsure, 0 not critical") {
		t.Errorf("subject = %q", subj)
	}
	txt, _ := os.ReadFile(filepath.Join(dir, "digest.txt"))
	if !strings.Contains(string(txt), "No judgement was available") {
		t.Errorf("the digest does not say why:\n%s", txt)
	}
	// No project is set, so each Unsure needed an item and none could be filed:
	// nothing is recorded as reported, so the next run tries again.
	var recs []supplier.SeenRecord
	sb, _ := os.ReadFile(filepath.Join(dir, "seen.json"))
	if err := json.Unmarshal(sb, &recs); err != nil || len(recs) != 0 {
		t.Errorf("seen.json = %s (%v): a request whose item failed must not be recorded", sb, err)
	}
	// No project set: each Unsure needed an item and none could be filed, so the
	// runner has a problem to report after the digest goes out.
	if pb, _ := os.ReadFile(filepath.Join(dir, "problems.txt")); !strings.Contains(string(pb), "SUPPLIER_JIRA_PROJECT") {
		t.Errorf("problems = %q", pb)
	}
}

func TestFinishUsesTheModelsJudgementWhenItIsThere(t *testing.T) {
	dir := setup(t, twoItems())
	no := `{"schema":"cti-supplier/1","message_id":"b","verdict":"no","reason":"gravel","evidence":["SUBJECT: New supplier request"]}`
	if err := os.WriteFile(filepath.Join(dir, "001.result.json"), []byte(no), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := doFinish(dir, false); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	subj, _ := os.ReadFile(filepath.Join(dir, "digest.subject"))
	if !strings.Contains(string(subj), "0 critical, 1 unsure, 1 not critical") {
		t.Errorf("subject = %q", subj)
	}
	// The No needs no item, so it is recorded; the Unsure could not be filed.
	var recs []supplier.SeenRecord
	sb, _ := os.ReadFile(filepath.Join(dir, "seen.json"))
	if err := json.Unmarshal(sb, &recs); err != nil || len(recs) != 1 || recs[0].Entry.Verdict != "no" {
		t.Errorf("seen.json = %s (%v)", sb, err)
	}
}

func TestNoRequestsWritesNoDigest(t *testing.T) {
	dir := setup(t, nil)
	if code := doFinish(dir, false); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "digest.subject")); err == nil {
		t.Error("a day with no requests wrote a digest")
	}
}

func TestCommitSeenRecordsLabelsAndRefusesNoStateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SUPPLIER_SEEN_FILE", "")
	t.Setenv("FLEET_HOME", home)
	f := filepath.Join(t.TempDir(), "seen.json")
	rec := `[{"label":"fleet-supplier-abc","entry":{"last_received":"2026-11-05T09:00:00Z","verdict":"unsure","ticket":"CYBR-7"}}]`
	if err := os.WriteFile(f, []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := doCommitSeen(f); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	s, err := supplier.LoadSeen(filepath.Join(home, "state", "supplier-seen.json"))
	if err != nil || !s.Has("fleet-supplier-abc") || s["fleet-supplier-abc"].Ticket != "CYBR-7" || s["fleet-supplier-abc"].Verdict != "unsure" {
		t.Errorf("%v %v", s, err)
	}
	t.Setenv("FLEET_HOME", "")
	if code := doCommitSeen(f); code == exitOK {
		t.Error("committed with no state directory")
	}
}

func TestTheOperatorsTechWordListReplacesTheDefault(t *testing.T) {
	t.Setenv("SUPPLIER_TECH_TERMS", "")
	if c := laneConfig(); c.TechTerms == nil || len(c.TechTerms) != 0 {
		t.Errorf("set-and-empty should mean no words: %#v", c.TechTerms)
	}
	t.Setenv("SUPPLIER_TECH_TERMS", " Robot , drone ")
	if c := laneConfig(); len(c.TechTerms) != 2 || c.TechTerms[0] != "Robot" {
		t.Errorf("%#v", c.TechTerms)
	}
	if err := os.Unsetenv("SUPPLIER_TECH_TERMS"); err != nil {
		t.Fatal(err)
	}
	if c := laneConfig(); c.TechTerms != nil {
		t.Errorf("unset should be the defaults (nil): %#v", c.TechTerms)
	}
}

func TestTheAutomaticCountReachesTheDigest(t *testing.T) {
	dir := t.TempDir()
	if err := writeItems(dir, supplier.Collected{Items: twoItems(), Automatic: 3}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"SUPPLIER_JIRA_PROJECT", "SUPPLIER_BOARD_URL", "SUPPLIER_TECH_TERMS", "FLEET_ORG"} {
		t.Setenv(k, "")
	}
	if code := doFinish(dir, false); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	txt, _ := os.ReadFile(filepath.Join(dir, "digest.txt"))
	if !strings.Contains(string(txt), "3 automatic messages from the mail filter left out") {
		t.Errorf("digest.txt:\n%s", txt)
	}
}

func TestTheListOfEmailsReadReachesTheDigestWithWhatCameOfEach(t *testing.T) {
	dir := t.TempDir()
	items := twoItems()
	rows := []supplier.MailRow{
		{Label: items[0].Request.Label(), Received: time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC), From: "a@example.test", Subject: "Cloud Backup Inc", Handling: supplier.HandledNew},
		{Received: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC), From: "filter@example.test", Subject: "End User Digest", Handling: supplier.HandledAutomatic},
		{Label: "fleet-supplier-0000000000000000", Received: time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC), From: "b@example.test", Subject: "Old one", Handling: supplier.HandledReported},
	}
	if err := writeItems(dir, supplier.Collected{Items: items, Read: rows}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"SUPPLIER_JIRA_PROJECT", "SUPPLIER_BOARD_URL", "SUPPLIER_TECH_TERMS", "FLEET_ORG"} {
		t.Setenv(k, "")
	}
	t.Setenv("SUPPLIER_JIRA_PROJECT", "CYBR") // a dry run files nothing, but a project means an item could be filed
	if code := doFinish(dir, false); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	txt, _ := os.ReadFile(filepath.Join(dir, "digest.txt"))
	for _, want := range []string{"EMAILS READ THIS RUN - 3 MESSAGES IN 2 REQUESTS", "Cloud Backup Inc", "[Unsure]",
		"[Left out: automatic message from the mail filter]", "[Reported earlier, nothing new]"} {
		if !strings.Contains(string(txt), want) {
			t.Errorf("digest.txt lacks %q:\n%s", want, txt)
		}
	}
}

func TestSplitListDropsEmpties(t *testing.T) {
	got := splitList(" a@example.test, ,b@example.test,")
	if len(got) != 2 || got[0] != "a@example.test" || got[1] != "b@example.test" {
		t.Errorf("%#v", got)
	}
}
