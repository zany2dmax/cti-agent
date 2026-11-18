package falcon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "s3cret-value-never-printed"

func TestOnlyTheCrowdStrikeAPIHostsAreAccepted(t *testing.T) {
	good := map[string]string{
		"api.us-2.crowdstrike.com":          "https://api.us-2.crowdstrike.com",
		"https://api.us-2.crowdstrike.com":  "https://api.us-2.crowdstrike.com",
		"https://API.US-2.crowdstrike.com/": "https://api.us-2.crowdstrike.com",
		" https://api.crowdstrike.com ":     "https://api.crowdstrike.com",
		"api.eu-1.crowdstrike.com":          "https://api.eu-1.crowdstrike.com",
	}
	for in, want := range good {
		got, err := NormalizeBase(in)
		if err != nil || got != want {
			t.Errorf("NormalizeBase(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"",
		"http://api.us-2.crowdstrike.com",       // not https
		"https://api.us-2.crowdstrike.com:8443", // port
		"https://api.us-2.crowdstrike.com/oauth2",  // path
		"https://api.us-2.crowdstrike.com/?x=1",    // query
		"https://user:pw@api.us-2.crowdstrike.com", // credentials
		"https://api.us-2.crowdstrike.com.evil.example",
		"https://evil.example/api.us-2.crowdstrike.com",
		"https://falcon.us-2.crowdstrike.com", // the console, not the API
		"https://crowdstrike.com",
		"ftp://api.crowdstrike.com",
	}
	for _, in := range bad {
		if got, err := NormalizeBase(in); err == nil {
			t.Errorf("NormalizeBase(%q) = %q, want an error", in, got)
		}
	}
}

func TestNewNeedsBothCredentials(t *testing.T) {
	if _, err := New("api.us-2.crowdstrike.com", "", "x"); err == nil {
		t.Fatal("no client ID: want an error")
	}
	if _, err := New("api.us-2.crowdstrike.com", "id", " "); err == nil {
		t.Fatal("blank secret: want an error")
	}
	c, err := New("api.us-2.crowdstrike.com", "id", "x")
	if err != nil || c.Region() != "us-2" || c.Host() != "api.us-2.crowdstrike.com" {
		t.Fatalf("New = %v, %v", c, err)
	}
}

// fake is a minimal Falcon: a token endpoint and a router for GETs.
type fake struct {
	tokens   atomic.Int32
	revoked  atomic.Int32
	tokenFn  func(w http.ResponseWriter, r *http.Request)
	routes   map[string]func(w http.ResponseWriter, r *http.Request)
	lastAuth atomic.Value
}

func newFake(t *testing.T) (*fake, *Client) {
	t.Helper()
	f := &fake{routes: map[string]func(http.ResponseWriter, *http.Request){}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			f.tokens.Add(1)
			if f.tokenFn != nil {
				f.tokenFn(w, r)
				return
			}
			_ = r.ParseForm()
			if r.PostForm.Get("client_id") != "id" || r.PostForm.Get("client_secret") != testSecret {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"errors":[{"code":401,"message":"access denied, invalid client"}]}`))
				return
			}
			w.WriteHeader(201)
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"bearer","expires_in":1799}`, f.tokens.Load())
		case "/oauth2/revoke":
			f.revoked.Add(1)
			if id, sec, ok := r.BasicAuth(); !ok || id != "id" || sec != testSecret {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(200)
		default:
			f.lastAuth.Store(r.Header.Get("Authorization"))
			if h, ok := f.routes[r.URL.Path]; ok {
				h(w, r)
				return
			}
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errors":[{"code":404,"message":"route not found"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newClient(srv.URL, "id", testSecret, srv.Client())
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return f, c
}

func ok(total int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"meta":{"pagination":{"total":%d}},"resources":["x"],"errors":[]}`, total)
	}
}

func TestTheTokenIsFetchedOnceAndReused(t *testing.T) {
	f, c := newFake(t)
	f.routes["/devices/queries/devices/v1"] = ok(7)
	for i := 0; i < 3; i++ {
		r, err := c.Get(context.Background(), "/devices/queries/devices/v1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if n, has := r.Total(); !has || n != 7 {
			t.Fatalf("total = %d, %v", n, has)
		}
	}
	if f.tokens.Load() != 1 {
		t.Fatalf("token fetched %d times, want 1", f.tokens.Load())
	}
	if got := f.lastAuth.Load(); got != "Bearer tok-1" {
		t.Fatalf("Authorization = %v", got)
	}
}

func TestABadSecretNeverAppearsInTheError(t *testing.T) {
	f, c := newFake(t)
	c.secret = "wrong-" + testSecret
	f.tokenFn = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// A hostile or buggy server echoing the request back.
		w.WriteHeader(401)
		_, _ = fmt.Fprintf(w, `{"echo":%q,"errors":[{"code":401,"message":"access denied\r\nFAKE LOG LINE"}]}`, r.PostForm.Encode())
	}
	_, err := c.Token(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if strings.Contains(msg, testSecret) || strings.Contains(msg, "client_secret") {
		t.Fatalf("error carries the request: %q", msg)
	}
	if strings.ContainsAny(msg, "\r\n") {
		t.Fatalf("error carries a line break: %q", msg)
	}
	if !strings.Contains(msg, "HTTP 401") || !strings.Contains(msg, "client ID or secret") {
		t.Fatalf("error does not say what is wrong: %q", msg)
	}
}

func TestTheWrongCloudNamesTheRightHost(t *testing.T) {
	c := newClient("https://api.crowdstrike.com", "id", testSecret, &http.Client{})
	if got := c.regionHint("us-2"); !strings.Contains(got, "FALCON_BASE_URL=https://api.us-2.crowdstrike.com") {
		t.Fatalf("hint = %q", got)
	}
	if got := c.regionHint("US-1"); got != "" {
		t.Fatalf("same region gave a hint: %q", got)
	}
	if got := c.regionHint("mars-9"); got != "" {
		t.Fatalf("unknown region gave a hint: %q", got)
	}
}

func TestATokenRefusalFromTheWrongCloudSaysSo(t *testing.T) {
	f, c := newFake(t)
	f.tokenFn = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Cs-Region", "eu-1")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":[{"code":403,"message":"access denied"}]}`))
	}
	_, err := c.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "api.eu-1.crowdstrike.com") {
		t.Fatalf("err = %v", err)
	}
}

func TestA429IsRetriedAfterTheAPIsOwnWait(t *testing.T) {
	f, c := newFake(t)
	var calls atomic.Int32
	var waited []time.Duration
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	c.sleep = func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }
	f.routes["/alerts/queries/alerts/v2"] = func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("X-Ratelimit-Retryafter", fmt.Sprint(now.Unix()+7))
			w.WriteHeader(429)
			return
		}
		ok(3)(w, r)
	}
	if _, err := c.Get(context.Background(), "/alerts/queries/alerts/v2", nil); err != nil {
		t.Fatal(err)
	}
	if len(waited) != 1 || waited[0] != 7*time.Second {
		t.Fatalf("waited %v, want [7s]", waited)
	}
}

func TestRetryWaitIsCapped(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if d := retryWait(fmt.Sprint(now.Unix()+3600), 1, now); d != maxRetryWait {
		t.Fatalf("an hour's wait became %v, want the %v cap", d, maxRetryWait)
	}
	if d := retryWait(fmt.Sprint(now.Unix()-5), 1, now); d != time.Second {
		t.Fatalf("a past time became %v, want 1s", d)
	}
	if d := retryWait("", 2, now); d != 20*time.Second {
		t.Fatalf("no header, attempt 2: %v", d)
	}
}

func TestA429ThatNeverClearsGivesUp(t *testing.T) {
	f, c := newFake(t)
	var calls atomic.Int32
	f.routes["/alerts/queries/alerts/v2"] = func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(429)
	}
	_, err := c.Get(context.Background(), "/alerts/queries/alerts/v2", nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 429 {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != getAttempts {
		t.Fatalf("%d calls, want %d", calls.Load(), getAttempts)
	}
}

func TestAnExpiredTokenIsRenewedOnce(t *testing.T) {
	f, c := newFake(t)
	f.routes["/devices/queries/devices/v1"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer tok-1" {
			w.WriteHeader(401)
			return
		}
		ok(1)(w, r)
	}
	if _, err := c.Get(context.Background(), "/devices/queries/devices/v1", nil); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 2 {
		t.Fatalf("tokens = %d, want 2", f.tokens.Load())
	}
	// A 401 that persists is reported, not looped on.
	f.routes["/devices/queries/devices/v1"] = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }
	if _, err := c.Get(context.Background(), "/devices/queries/devices/v1", nil); err == nil {
		t.Fatal("persistent 401: want an error")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	f, c := newFake(t)
	var followed atomic.Int32
	f.routes["/elsewhere"] = func(w http.ResponseWriter, _ *http.Request) { followed.Add(1); ok(1)(w, nil) }
	f.routes["/devices/queries/devices/v1"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}
	_, err := c.Get(context.Background(), "/devices/queries/devices/v1", nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 302 {
		t.Fatalf("err = %v, want HTTP 302", err)
	}
	if followed.Load() != 0 {
		t.Fatal("the redirect was followed, carrying the bearer token")
	}
}

func TestQueryValuesAreEscapedAndRoutesAreFixed(t *testing.T) {
	f, c := newFake(t)
	var raw string
	f.routes["/iocs/queries/indicators/devices/v1"] = func(w http.ResponseWriter, r *http.Request) {
		raw = r.URL.RawQuery
		ok(0)(w, r)
	}
	q := map[string][]string{"type": {"domain"}, "value": {"a.example&type=sha256"}}
	if _, err := c.Get(context.Background(), "/iocs/queries/indicators/devices/v1", q); err != nil {
		t.Fatal(err)
	}
	if strings.Count(raw, "type=") != 1 || !strings.Contains(raw, "%26type%3Dsha256") {
		t.Fatalf("query was not escaped: %q", raw)
	}
	for _, bad := range []string{"devices", "/a?b=1", "/a#x", "/../oauth2/token"} {
		if _, err := c.Get(context.Background(), bad, nil); err == nil {
			t.Errorf("route %q accepted", bad)
		}
	}
}

func TestProbesReportEachScope(t *testing.T) {
	f, c := newFake(t)
	f.routes["/devices/queries/devices/v1"] = ok(1200)
	f.routes["/discover/queries/applications/v1"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":[{"code":403,"message":"access denied, authorization failed"}]}`))
	}
	// The service's own "nothing matched": an envelope with a trace_id.
	f.routes["/iocs/queries/indicators/devices/v1"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"meta":{"trace_id":"t-1"},"resources":[],"errors":[{"code":404,"message":"No resources found"}]}`))
	}
	f.routes["/alerts/queries/alerts/v2"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"errors":[{"code":500,"message":"internal"}]}`))
	}
	got := map[string]ProbeResult{}
	for _, p := range Probes {
		got[p.Scope] = c.RunProbe(context.Background(), p)
	}
	if r := got["Hosts: READ"]; r.Result != ProbeOK || r.Total == nil || *r.Total != 1200 {
		t.Errorf("hosts = %+v", r)
	}
	if r := got["Assets: READ"]; r.Result != ProbeDenied || !strings.Contains(r.Detail, "Discover") {
		t.Errorf("assets = %+v", r)
	}
	if r := got["IOC Management: READ"]; r.Result != ProbeOK || r.HTTP != 404 {
		t.Errorf("ioc = %+v", r)
	}
	if r := got["Alerts: READ"]; r.Result != ProbeError || r.HTTP != 500 {
		t.Errorf("alerts = %+v", r)
	}
}

func TestEveryProbeIsARead(t *testing.T) {
	// The probes are GETs by construction (Get is the only request method
	// this package has); this pins that each one asks for at most one row.
	for _, p := range Probes {
		if l := p.Query.Get("limit"); l != "1" {
			t.Errorf("%s: limit=%q, want 1", p.Scope, l)
		}
		if !strings.HasPrefix(p.Path, "/") {
			t.Errorf("%s: path %q", p.Scope, p.Path)
		}
	}
}

func TestRevokeEndsTheTokenAndIsSafeTwice(t *testing.T) {
	f, c := newFake(t)
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.revoked.Load() != 1 {
		t.Fatalf("revoked %d times, want 1", f.revoked.Load())
	}
}

func TestA404ForAMissingRouteIsAnErrorNotNoHosts(t *testing.T) {
	_, c := newFake(t)
	var ioc Probe
	for _, p := range Probes {
		if p.NotFoundOK {
			ioc = p
		}
	}
	// The fake has no IOC route: its 404 has no trace_id and says "route".
	if r := c.RunProbe(context.Background(), ioc); r.Result != ProbeError {
		t.Fatalf("a missing route passed as %+v", r)
	}
	for _, he := range []*HTTPError{
		{Status: 404, FromAPI: true, Message: "route not found"},
		{Status: 404, FromAPI: false, Message: "No resources found"},
	} {
		if emptyAnswer(he) {
			t.Errorf("emptyAnswer(%+v) = true", he)
		}
	}
	if !emptyAnswer(&HTTPError{Status: 404, FromAPI: true, Message: "No resources found"}) {
		t.Error("the service's own empty answer was not recognised")
	}
}

func TestA401ForAnOldTokenDoesNotDropANewOne(t *testing.T) {
	_, c := newFake(t)
	old, _, err := c.currentToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.token = "newer"
	c.mu.Unlock()
	c.dropToken(old)
	if tok, _, _ := c.currentToken(context.Background()); tok != "newer" {
		t.Fatalf("token = %q: a stale 401 dropped the fresh token", tok)
	}
	c.dropToken("newer")
	if tok, _, _ := c.currentToken(context.Background()); tok == "newer" || tok == "" {
		t.Fatalf("token = %q after drop, want a fresh fetch", tok)
	}
}

func TestTokenReportsTheRealExpiryEveryTime(t *testing.T) {
	_, c := newFake(t)
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	first, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := c.Token(context.Background())
	if !first.Equal(again) || !first.Equal(now.Add(1799*time.Second)) {
		t.Fatalf("expiry %v then %v, want %v both times", first, again, now.Add(1799*time.Second))
	}
}
