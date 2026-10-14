package domains

import (
	"strings"
	"testing"
	"time"
)

func TestProfileOfFollowsTheChart(t *testing.T) {
	for _, c := range []struct {
		e    Entry
		want Profile
	}{
		{Entry{Sends: true, Receives: true}, ProfileActive},
		{Entry{Sends: true}, ProfileSendOnly},
		{Entry{Receives: true}, ProfileReceiveOnly},
		{Entry{}, ProfileNoMail},
		{Entry{SaaS: true, Sends: true}, ProfileSaaS},
		{Entry{Unknown: true, Sends: true, Receives: true}, ProfileUnknown},
		{Entry{Sends: true, Receives: true, Legacy: true}, ProfileLegacyActive},
		{Entry{Receives: true, Legacy: true}, ProfileLegacyReceive},
	} {
		if got := ProfileOf(c.e); got != c.want {
			t.Errorf("%+v: %s, want %s", c.e, got, c.want)
		}
	}
}

func TestTheInventoryUnderstandsTheNewMarkers(t *testing.T) {
	in := "a.example send receive\nb.example receive legacy\nc.example saas\nd.example unknown\n"
	got, problems, err := ParseInventory(strings.NewReader(in))
	if err != nil || len(problems) != 0 {
		t.Fatalf("err=%v problems=%v", err, problems)
	}
	want := []Profile{ProfileActive, ProfileLegacyReceive, ProfileSaaS, ProfileUnknown}
	for i, e := range got {
		if ProfileOf(e) != want[i] {
			t.Errorf("%s: %s, want %s", e.Name, ProfileOf(e), want[i])
		}
	}
}

func mailOf(d string, spf, dmarc, mx []string) Mail {
	l := func(v []string) Lookup {
		if len(v) == 0 {
			return Lookup{Absent: true}
		}
		return Lookup{Values: v}
	}
	return Mail{SPF: l(spf), DMARC: l(dmarc), MX: l(mx), DMARCFrom: d}
}

func byHost(a []Action) map[string]Action {
	out := map[string]Action{}
	for _, x := range a {
		out[x.Type+" "+x.Host] = x
	}
	return out
}

func TestAnUnusedDomainGetsExactLockDownRecords(t *testing.T) {
	m := mailOf("parked.example", []string{"v=spf1 include:mail.example.test ~all"},
		[]string{"v=DMARC1; p=none; pct=50; rua=mailto:dmarc@example.com"},
		[]string{"mx1.example-mail.test"})
	m.DKIM.Found = []string{"selector1"}
	got := byHost(Actions([]Result{{Entry: Entry{Name: "parked.example"}, Mail: m}}, ""))

	if a := got["TXT @"]; a.Set != "v=spf1 -all" || a.Replace == "" {
		t.Errorf("SPF action = %+v", a)
	}
	// p= raised, pct dropped, the existing rua kept.
	if a := got["TXT _dmarc"]; a.Set != "v=DMARC1; p=reject; rua=mailto:dmarc@example.com" {
		t.Errorf("DMARC action = %+v", a)
	}
	if a := got["MX @"]; a.Set != "0 ." || !strings.Contains(a.Why, "CHECK no mailbox") {
		t.Errorf("MX action = %+v", a)
	}
	if a := got["TXT selector1._domainkey"]; !a.Delete {
		t.Errorf("DKIM action = %+v", a)
	}
}

func TestAReceiveOnlyDomainKeepsItsMX(t *testing.T) {
	m := mailOf("old.example", nil, nil, []string{"old-example.mail.protection.example.test"})
	got := byHost(Actions([]Result{{Entry: Entry{Name: "old.example", Receives: true, Legacy: true}, Mail: m}},
		"dmarc@example.com"))
	if _, ok := got["MX @"]; ok {
		t.Error("asked to replace the MX of a domain that receives mail")
	}
	if a := got["TXT @"]; a.Set != "v=spf1 -all" || a.Replace != "" {
		t.Errorf("SPF action = %+v", a)
	}
	if a := got["TXT _dmarc"]; a.Set != "v=DMARC1; p=reject; rua=mailto:dmarc@example.com" {
		t.Errorf("DMARC action = %+v", a)
	}
}

func TestALockedDomainNeedsNothing(t *testing.T) {
	m := mailOf("done.example", []string{"v=spf1 -all"}, []string{"v=DMARC1; p=reject"}, []string{"."})
	if a := Actions([]Result{{Entry: Entry{Name: "done.example"}, Mail: m}}, ""); len(a) != 0 {
		t.Errorf("actions for a locked domain: %+v", a)
	}
}

func TestSendersGetExactRecordsOnlyWhereTheAnswerIsCertain(t *testing.T) {
	// No DMARC: start at p=none, exact. SPF present and fine: nothing.
	m := mailOf("live.example", []string{"v=spf1 include:mail.example.test -all"}, nil, []string{"mx.example.test"})
	got := byHost(Actions([]Result{{Entry: Entry{Name: "live.example", Sends: true, Receives: true}, Mail: m}},
		"dmarc@example.com"))
	if a := got["TXT _dmarc"]; a.Set != "v=DMARC1; p=none; rua=mailto:dmarc@example.com" {
		t.Errorf("DMARC action = %+v", a)
	}
	if _, ok := got["TXT @"]; ok {
		t.Error("a working sender SPF was changed")
	}

	// Row 10: SPF over the lookup limit is a review item, and holds back the
	// DMARC p=none -> quarantine suggestion.
	m = mailOf("busy.example", []string{"v=spf1 include:a include:b -all"}, []string{"v=DMARC1; p=none"}, []string{"mx"})
	m.SPFLookups = 12
	got = byHost(Actions([]Result{{Entry: Entry{Name: "busy.example", Sends: true, Receives: true}, Mail: m}}, ""))
	if a := got["TXT @"]; a.Exact() || !strings.Contains(a.Why, "fix it first") {
		t.Errorf("SPF action = %+v", a)
	}
	if _, ok := got["TXT _dmarc"]; ok {
		t.Error("asked for DMARC enforcement while SPF is broken")
	}
}

func TestUnknownSendersAreNeverTightened(t *testing.T) {
	m := mailOf("who.example", nil, nil, []string{"mx"})
	if a := Actions([]Result{{Entry: Entry{Name: "who.example", Unknown: true}, Mail: m}}, ""); len(a) != 0 {
		t.Errorf("actions for an unknown-senders domain: %+v", a)
	}
}

func TestAFailedLookupIsNeverAChange(t *testing.T) {
	m := Mail{SPF: Lookup{Err: "timeout"}, DMARC: Lookup{Err: "timeout"}, MX: Lookup{Err: "timeout"},
		DMARCFrom: "slow.example"}
	if a := Actions([]Result{{Entry: Entry{Name: "slow.example"}, Mail: m}}, ""); len(a) != 0 {
		t.Errorf("actions from failed lookups: %+v", a)
	}
}

func TestActionsFileAndCSV(t *testing.T) {
	a := []Action{
		{Domain: "a.example", Type: "TXT", Host: "@", Set: "v=spf1 -all", Why: "w"},
		{Domain: "b.example", Type: "TXT", Host: "@", Why: "review"},
	}
	f := NewActionsFile(time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC), a)
	if f.Exact != 1 || f.Review != 1 || f.Domains != 2 || f.Hash == "" {
		t.Errorf("file = %+v", f)
	}
	if f.Hash == ActionsHash(a[:1]) {
		t.Error("different lists share a hash")
	}
	csv := string(ActionsCSV(a))
	if !strings.HasPrefix(csv, "domain,chart_row,type,host,action,") || !strings.Contains(csv, "'@") {
		t.Errorf("csv =\n%s", csv)
	}
	if empty := NewActionsFile(time.Now(), nil); empty.Actions == nil {
		t.Error("an empty list must serialise as [], not null")
	}
}
