package main

import (
	"os"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// results reads the real-shaped results notice and gives it an invented title.
func results(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../internal/vmscan/testdata/results-north-east.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "Scan Title") && strings.Contains(l, ":") && !strings.Contains(l, "display:none") {
			title := strings.TrimSpace(l[strings.Index(l, ":")+1:])
			return strings.ReplaceAll(s, title, "Example Weekly")
		}
	}
	t.Fatal("fixture has no Scan Title line")
	return ""
}

const fixtureStart = "11/05/2026 at 01:00:22 PM (GMT+0000)"

func completed(ref string) string {
	return `<pre>
   Scan Title       : Example Weekly
   Start Date       : ` + fixtureStart + `
   Scan Status      : Finished
<a href="https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com/fo/report/report_view.php?ref=scan*` + ref + `&amp;em=1__;Lw!!A!B$">link</a>
</pre>`
}

func TestCompanionsOfAReportedRunAreClaimedForDeletion(t *testing.T) {
	body := results(t)
	msgs := []graph.Message{
		{ID: "res", From: "qualys@qualys.net", AuthenticationResults: qualysAuth, Subject: "Qualys: Scan Results", BodyHTML: body},
		{ID: "done", From: "qualys@qualys.net", AuthenticationResults: qualysAuth, Subject: "Qualys: Scan Completed",
			BodyHTML: completed("1793275220.51060")},
		{ID: "task", From: "qualys@qualys.net", AuthenticationResults: qualysAuth, Subject: "Qualys: Completed Vulnerability Scan Notification",
			BodyHTML: "<pre>Title : Example Weekly\nLaunch Time : " + fixtureStart + "\n</pre>"},
		// Same subject from the team mailbox: a lookalike, never deleted.
		{ID: "fake", From: "team@example.com", Subject: "Qualys: Scan Completed",
			BodyHTML: completed("1793275220.51060")},
		// Another run of the same scan.
		{ID: "other", From: "qualys@qualys.net", AuthenticationResults: qualysAuth, Subject: "Qualys: Scan Completed",
			BodyHTML: completed("1793999999.99999")},
	}
	_, seen, _ := collect(msgs, []string{"Example Weekly"})
	got := map[string]bool{}
	for _, s := range seen {
		got[s.ID] = s.Delete
	}
	if d, ok := got["res"]; !ok || d {
		t.Errorf("results notice: claimed=%v delete=%v - it is archived, not deleted", ok, d)
	}
	for _, id := range []string{"done", "task"} {
		if d, ok := got[id]; !ok || !d {
			t.Errorf("%s: claimed=%v delete=%v, want a delete claim", id, ok, d)
		}
	}
	for _, id := range []string{"fake", "other"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s was claimed and would be deleted", id)
		}
	}
}

func TestAnUnfinishedRunKeepsItsCompanions(t *testing.T) {
	body := strings.Replace(results(t), ": Finished", ": Canceled", 1)
	msgs := []graph.Message{
		{ID: "res", From: "qualys@qualys.net", AuthenticationResults: qualysAuth, Subject: "Qualys: Scan Results", BodyHTML: body},
		{ID: "done", From: "qualys@qualys.net", AuthenticationResults: qualysAuth, Subject: "Qualys: Scan Completed",
			BodyHTML: completed("1793275220.51060")},
	}
	scans, seen, _ := collect(msgs, []string{"Example Weekly"})
	if len(scans) != 1 || scans[0].Finished() {
		t.Fatalf("fixture edit did not make an unfinished run: %+v", scans)
	}
	claimedResults := false
	for _, s := range seen {
		claimedResults = claimedResults || s.ID == "res"
		if s.ID == "done" {
			t.Error("the companion of a run that did not finish was claimed; it stays for a person")
		}
	}
	if !claimedResults {
		t.Error("the results notice should still be claimed - only its companions stay")
	}
}

// qualysAuth is Exchange Online's verdict on a genuine notice (synthetic).
const qualysAuth = "spf=pass smtp.mailfrom=qualys.net; dkim=pass header.d=qualys.net;" +
	"dmarc=pass action=none header.from=qualys.net;compauth=pass reason=100"
