package httpx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	ok := []string{
		"https://example.com/x", "HTTPS://EXAMPLE.COM", "http://127.0.0.1:8080/x",
		"http://localhost/x", "http://[::1]:9/x",
	}
	bad := []string{
		"http://example.com/x", "http://192.0.2.10/x", "ftp://example.com/x",
		"file:///etc/passwd", "http://127.0.0.1.example.com/x", "http://localhost.example.com",
		"//example.com/x",
	}
	for _, s := range ok {
		u, _ := url.Parse(s)
		if err := Check(u); err != nil {
			t.Errorf("Check(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range bad {
		u, _ := url.Parse(s)
		if err := Check(u); err == nil {
			t.Errorf("Check(%q) = nil, want an error", s)
		}
	}
}

func TestCheckErrorNamesHostNotQuery(t *testing.T) {
	u, _ := url.Parse("http://example.com/path?token=SECRET")
	err := Check(u)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "path") {
		t.Fatalf("error leaks the path or query: %v", err)
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error should name the host: %v", err)
	}
}

func TestTransportHasTheTLSFloor(t *testing.T) {
	tr := Transport()
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %+v, want TLS 1.2", tr.TLSClientConfig)
	}
}

func TestNewRefusesPlainHTTPBeforeSending(t *testing.T) {
	sent := false
	// A non-loopback http URL never reaches the network, so the base must
	// not be called. Stand in for the network with a base that records.
	c := &http.Client{Transport: Guard(roundTripFunc(func(*http.Request) (*http.Response, error) {
		sent = true
		return nil, nil
	}))}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Basic c2VjcmV0")
	if _, err := c.Do(req); err == nil { // #nosec G704 -- test
		t.Fatal("plain http to a non-loopback host was allowed")
	}
	if sent {
		t.Fatal("the request reached the base transport")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewAllowsLoopbackHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	resp, err := New(5 * time.Second).Get(srv.URL) // #nosec G107 G704 -- loopback test server
	if err != nil {
		t.Fatalf("loopback http refused: %v", err)
	}
	_ = resp.Body.Close()
}

func TestRedirectToPlainHTTPIsRefused(t *testing.T) {
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "example.com"}}}
	req := &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/x"}}
	if err := CheckRedirect(req, via); err == nil {
		t.Fatal("a downgrade redirect was allowed")
	}
	req.URL.Scheme = "https"
	if err := CheckRedirect(req, via); err != nil {
		t.Fatalf("an https redirect was refused: %v", err)
	}
	long := make([]*http.Request, maxRedirects)
	if err := CheckRedirect(req, long); err == nil {
		t.Fatal("redirect chain was not bounded")
	}
}
