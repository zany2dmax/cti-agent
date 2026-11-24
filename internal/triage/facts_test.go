package triage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/falcon"
)

type fakeSource struct {
	apps    map[string]*falcon.AppSearch
	seen    map[string]int
	alerts  map[string]int
	asked   []string
	sawName []string
}

func (f *fakeSource) FindApps(_ context.Context, name string, _ falcon.FindOpts) (*falcon.AppSearch, error) {
	f.sawName = append(f.sawName, name)
	if r, ok := f.apps[name]; ok {
		return r, nil
	}
	return &falcon.AppSearch{}, nil
}

func (f *fakeSource) SeenOn(_ context.Context, ind string) (int, error) {
	f.asked = append(f.asked, ind)
	if ind == "boom.example" {
		return 0, errors.New("falcon down")
	}
	return f.seen[ind], nil
}

func (f *fakeSource) TechniqueAlerts(_ context.Context, t string, _ time.Time) (int, string, error) {
	parent := strings.SplitN(t, ".", 2)[0]
	return f.alerts[parent], parent, nil
}

func (f *fakeSource) Sensors(context.Context) (int, error) { return 2128, nil }

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		c    int
		ok   bool
	}{
		{"157.0.8089.0", "157.0.8100", -1, true},
		{"131.0.6778.86", "131.0.6778.86", 0, true},
		{"131.0.6778.86.0", "131.0.6778.86", 0, true},
		{"132", "131.9.9", 1, true},
		{"5.0 (1018.5.5)", "5.1", 0, false},
		{"2.43-2ubuntu2.7", "2.44", 0, false},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		if got != c.c || ok != c.ok {
			t.Errorf("compareVersions(%q, %q) = %d, %v; want %d, %v", c.a, c.b, got, ok, c.c, c.ok)
		}
	}
}

func TestIndicatorsAreRefangedAndLinksOnlyWhenDefanged(t *testing.T) {
	body := "C2 at evil[.]example and 203.0.113.9; payload sha256 " + strings.Repeat("a", 64) +
		". See hxxps://drop[.]example/x and https://www.microsoft.com/advisory"
	ex := Extract(body)
	got := strings.Join(indicators(body, ex), " ")
	for _, want := range []string{"evil.example", "203.0.113.9", strings.Repeat("a", 64), "drop.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("indicators %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "microsoft.com") {
		t.Errorf("an ordinary reference link was treated as an indicator: %q", got)
	}
}

func TestGatherBuildsTheSheetFromFactsOnly(t *testing.T) {
	src := &fakeSource{
		apps: map[string]*falcon.AppSearch{"Chrome": {Total: 30, Apps: []falcon.AppSummary{{
			Vendor: "Google LLC", Name: "Google Chrome", Hosts: 10,
			Versions:  map[string]int{"131.0.6778.85": 6, "131.0.6778.86": 3, "weird": 1},
			HostTypes: map[string]int{"Workstation": 9, "Server": 1}, Exposure: map[string]int{"unknown": 10},
		}}}},
		seen:   map[string]int{"evil.example": 2},
		alerts: map[string]int{"T1566": 4},
	}
	body := "Chrome before 131.0.6778.86 is exploited. C2 evil[.]example, boom[.]example, 198.51.100.7 (T1566.002)."
	ex := Extract(body)
	subj := &Subjects{Schema: SubjectsSchema, Items: []Subject{
		{Product: "Chrome", Vendor: "Google", FixedIn: "131.0.6778.86", Techniques: []string{"T1566.002", "T1203"}, Inferred: []string{"T1203"}},
		{Product: "x'+vendor:*", Title: "hostile"},
	}}
	fs := Gather(context.Background(), src, body, ex, subj, nil, time.Now(), "Site A; Site B")
	if fs.Sensors != 2128 || fs.BlindSpots != "Site A; Site B" {
		t.Errorf("sheet header = %+v", fs)
	}
	chrome := fs.Subjects[0]
	if len(chrome.Apps) != 1 {
		t.Fatalf("chrome = %+v", chrome)
	}
	a := chrome.Apps[0]
	if !a.VendorMatches || a.BelowFixed == nil || *a.BelowFixed != 6 || a.UncomparedHosts != 1 || a.Exposure != nil {
		t.Errorf("app fact = %+v", a)
	}
	if fs.Subjects[1].Skipped == "" || len(src.sawName) != 1 {
		t.Errorf("a hostile product name reached the lookup: %v / %+v", src.sawName, fs.Subjects[1])
	}
	byVal := map[string]IndicatorFact{}
	for _, i := range fs.Indicators {
		byVal[i.Value] = i
	}
	if byVal["evil.example"].Hosts != 2 || byVal["boom.example"].Error == "" || byVal["198.51.100.7"].Type != falcon.IOCIPv4 {
		t.Errorf("indicators = %+v", fs.Indicators)
	}
	var srcs []string
	for _, tf := range fs.Techniques {
		srcs = append(srcs, tf.ID+"="+tf.Source)
	}
	if strings.Join(srcs, " ") != "T1566.002=advisory T1203=reader" || fs.Techniques[0].Alerts != 4 || fs.Techniques[0].Asked != "T1566" {
		t.Errorf("techniques = %+v", fs.Techniques)
	}
}

func TestIndicatorLookupsAreCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString("host" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "[.]example ")
	}
	src := &fakeSource{}
	fs := Gather(context.Background(), src, b.String(), Extract(b.String()), nil, nil, time.Now(), "")
	if len(src.asked) != maxIndicatorLookups || len(fs.Indicators) != 40 {
		t.Fatalf("asked %d, listed %d", len(src.asked), len(fs.Indicators))
	}
}
