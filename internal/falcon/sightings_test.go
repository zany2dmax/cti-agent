package falcon

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIndicatorsAreClassifiedExactly(t *testing.T) {
	good := map[string]string{
		"Evil.Example":          IOCDomain,
		"203.0.113.9":           IOCIPv4,
		"2001:db8::1":           IOCIPv6,
		strings.Repeat("a", 32): IOCMD5,
		strings.Repeat("B", 64): IOCSHA256,
	}
	for in, want := range good {
		if typ, _, err := ClassifyIndicator(in); err != nil || typ != want {
			t.Errorf("ClassifyIndicator(%q) = %q, %v; want %q", in, typ, err, want)
		}
	}
	for _, bad := range []string{"", "evil", "evil.example/path", "a@b.example", "evil.example'+x", strings.Repeat("a", 40), "-x.example", "1.2.3"} {
		if typ, _, err := ClassifyIndicator(bad); err == nil {
			t.Errorf("ClassifyIndicator(%q) = %q, want refused", bad, typ)
		}
	}
}

func TestSeenOnCountsAndTheServicesEmptyAnswerIsNone(t *testing.T) {
	f, c := newFake(t)
	var got []string
	f.routes["/iocs/queries/indicators/devices/v1"] = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		got = append(got, q.Get("type")+"="+q.Get("value"))
		if q.Get("value") == "quiet.example" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"meta":{"trace_id":"t"},"resources":[],"errors":[{"code":404,"message":"No resources found"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"pagination":{"total":3}},"resources":["a","b","c"]}`))
	}
	if n, err := c.SeenOn(context.Background(), "Loud.Example"); err != nil || n != 3 {
		t.Fatalf("loud: %d %v", n, err)
	}
	if n, err := c.SeenOn(context.Background(), "quiet.example"); err != nil || n != 0 {
		t.Fatalf("quiet: %d %v", n, err)
	}
	if _, err := c.SeenOn(context.Background(), "not an indicator"); err == nil {
		t.Fatal("a bad indicator was looked up")
	}
	if strings.Join(got, " ") != "domain=loud.example domain=quiet.example" {
		t.Fatalf("asked %v", got)
	}
}

func TestTechniqueAlertsAsksForTheParentInTheWindow(t *testing.T) {
	f, c := newFake(t)
	var filter string
	f.routes["/alerts/queries/alerts/v2"] = func(w http.ResponseWriter, r *http.Request) {
		filter = r.URL.Query().Get("filter")
		_, _ = w.Write([]byte(`{"meta":{"pagination":{"total":7}},"resources":[]}`))
	}
	since := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	n, asked, err := c.TechniqueAlerts(context.Background(), "t1566.002", since)
	if err != nil || n != 7 || asked != "T1566" {
		t.Fatalf("%d %q %v", n, asked, err)
	}
	if filter != "technique_id:'T1566'+created_timestamp:>'2026-10-19T00:00:00Z'" {
		t.Fatalf("filter = %q", filter)
	}
	if _, _, err := c.TechniqueAlerts(context.Background(), "T1566'+x", since); err == nil {
		t.Fatal("a hostile technique was looked up")
	}
}

func TestSensorsCountsOnlyRecentHosts(t *testing.T) {
	f, c := newFake(t)
	var filter string
	f.routes["/devices/queries/devices/v1"] = func(w http.ResponseWriter, r *http.Request) {
		filter = r.URL.Query().Get("filter")
		ok(2100)(w, r)
	}
	if n, err := c.Sensors(context.Background()); err != nil || n != 2100 {
		t.Fatalf("%d %v", n, err)
	}
	if !strings.HasPrefix(filter, "last_seen:>'") {
		t.Fatalf("filter = %q", filter)
	}
}
