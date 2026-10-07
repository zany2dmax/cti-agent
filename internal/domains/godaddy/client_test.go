package godaddy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDomainsRequestShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/domains" || r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-pat" {
			t.Errorf("Authorization = %q", got)
		}
		inc := r.URL.Query().Get("includes")
		// The one property of this client that matters most.
		if strings.Contains(strings.ToLower(inc), "authcode") {
			t.Errorf("requested authCode: includes=%q", inc)
			return
		}
		if inc != "nameServers" || r.URL.Query().Get("limit") != "1000" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprint(w, `[{"domain":"Example.COM","status":"active","expires":"2027-01-02T03:04:05.000Z",
		  "renewAuto":true,"locked":true,"privacy":false,
		  "nameServers":["NS2.example-dns.test.","ns1.example-dns.test","ns1.example-dns.test"]}]`)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "test-pat", HTTP: srv.Client()}
	got, err := c.Domains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	r := got[0]
	if r.Domain != "example.com" || r.Status != "ACTIVE" || !r.AutoRenew || !r.Locked ||
		r.Expires.Year() != 2027 {
		t.Errorf("normalised = %+v", r)
	}
	if strings.Join(r.NameServers, ",") != "ns1.example-dns.test,ns2.example-dns.test" {
		t.Errorf("nameservers = %v", r.NameServers)
	}
}

func TestDomainsPaginates(t *testing.T) {
	var markers []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := r.URL.Query().Get("marker")
		markers = append(markers, m)
		var rows []string
		n := pageSize
		if m != "" {
			n = 3 // short page ends the loop
		}
		for i := 0; i < n; i++ {
			rows = append(rows, fmt.Sprintf(`{"domain":"d%04d-%s.example"}`, i, strings.TrimSuffix(m, ".example")))
		}
		_, _ = fmt.Fprint(w, "["+strings.Join(rows, ",")+"]")
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	got, err := c.Domains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != pageSize+3 || len(markers) != 2 || markers[1] != "d0999-.example" {
		t.Errorf("got %d domains, markers %v", len(got), markers)
	}
}

func TestDomainsStuckMarkerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows := make([]string, pageSize)
		for i := range rows {
			rows[i] = `{"domain":"same.example"}`
		}
		_, _ = fmt.Fprint(w, "["+strings.Join(rows, ",")+"]")
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	if _, err := c.Domains(context.Background()); err == nil {
		t.Fatal("a marker that does not advance returned a list as if complete")
	}
}

func TestDomainsErrorsSayWhy(t *testing.T) {
	for code, want := range map[int]string{
		401: "expired or revoked",
		403: "domains.domain:read",
		429: "retry after 30",
		500: "HTTP 500",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(code)
			_, _ = fmt.Fprint(w, `{"code":"UNABLE_TO_AUTHENTICATE","message":"synthetic"}`)
		}))
		c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
		_, err := c.Domains(context.Background())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("HTTP %d: err = %v, want %q", code, err, want)
		}
	}
	if _, err := (&Client{}).Domains(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "GODADDY_PAT") {
		t.Errorf("no token: %v", err)
	}
}
