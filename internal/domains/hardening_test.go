package domains

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A page whose lower-cased form is a different length from the original
// ("İ" lower-cases to three bytes, not two) used to slice out of range and
// crash the whole weekly run.
func TestTitleSurvivesCharactersThatChangeLengthWhenLowerCased(t *testing.T) {
	body := []byte("<html><head>" + strings.Repeat("İ", 400) + "<TITLE>  Our   Site </Title></head>")
	if got := title(body); got != "Our Site" {
		t.Errorf("title = %q", got)
	}
	bad := append([]byte("<title>caf\xe9 shop</title>"), 0xff)
	if got := title(bad); got != "caf shop" {
		t.Errorf("invalid UTF-8 title = %q", got)
	}
	if got := title([]byte("<title>" + strings.Repeat("x", 200) + "</title>")); len([]rune(got)) != 83 {
		t.Errorf("a long title was not cut: %d", len([]rune(got)))
	}
	if title([]byte("no title here")) != "" || title([]byte("<title>unterminated")) != "" {
		t.Error("a missing title should be empty")
	}
}

func TestPublicIPClassification(t *testing.T) {
	for ip, want := range map[string]bool{
		"93.184.216.34": true, "2606:2800:220:1:248:1893:25c8:1946": true, "8.8.8.8": true,
		"127.0.0.1": false, "::1": false, "10.1.2.3": false, "172.16.0.9": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "224.0.0.1": false,
		"198.18.0.5": false, "fd00::1": false, "fe80::1": false, "::ffff:10.0.0.1": false, "240.0.0.1": false,
	} {
		if got := publicIP(net.ParseIP(ip)); got != want {
			t.Errorf("publicIP(%s) = %v, want %v", ip, got, want)
		}
	}
	if publicIP(nil) {
		t.Error("nil counted as public")
	}
	if got := nonPublic([]string{"93.184.216.34", "10.0.0.1", "127.0.0.1"}); len(got) != 2 {
		t.Errorf("nonPublic = %v", got)
	}
}

// A name that resolves to a private address is listed, not fetched; with the
// setting it is fetched as before. One private answer among public ones is
// enough: the DNS owner chooses what comes back.
func TestAHostThatResolvesPrivateIsNotFetchedUnlessAllowed(t *testing.T) {
	dns := fakeDNS{host: map[string][]string{
		"internal.example.com": {"10.9.8.7"},
		"mixed.example.com":    {"93.184.216.34", "169.254.169.254"},
		"public.example.com":   {"93.184.216.34"},
	}}
	calls := 0
	fetch := func(context.Context, string) (Fetch, Fetch, Cert) {
		calls++
		return Fetch{Tried: true, Status: 200}, Fetch{Tried: true, Status: 301}, Cert{Checked: true, Verified: true}
	}
	for _, h := range []string{"internal.example.com", "mixed.example.com"} {
		w := probeWeb(context.Background(), dns, fetch, h, false)
		if len(w.Private) == 0 || w.HTTPS.Tried {
			t.Errorf("%s was fetched: %+v", h, w)
		}
		if !w.Addrs.Present() {
			t.Errorf("%s lost its addresses", h)
		}
	}
	if calls != 0 {
		t.Fatalf("fetched %d times", calls)
	}
	if w := probeWeb(context.Background(), dns, fetch, "public.example.com", false); calls != 1 || w.Private != nil {
		t.Errorf("a public host was not fetched: %d calls, %+v", calls, w)
	}
	if w := probeWeb(context.Background(), dns, fetch, "internal.example.com", true); calls != 2 || !w.HTTPS.OK() {
		t.Errorf("DOMAINS_ALLOW_PRIVATE did not allow it: %d calls, %+v", calls, w)
	}
	// The report says so, as information, not as an unreachable site.
	w := probeWeb(context.Background(), dns, fetch, "internal.example.com", false)
	var got []Finding
	evalWeb("internal.example.com", w, now, func(string) bool { return true },
		func(d string, s Severity, cat, format string, a ...any) {
			got = append(got, Finding{Domain: d, Sev: s, Area: cat, Text: fmt.Sprintf(format, a...)})
		})
	if len(got) != 1 || got[0].Sev != Info || !strings.Contains(got[0].Text, "10.9.8.7") ||
		!strings.Contains(got[0].Text, "DOMAINS_ALLOW_PRIVATE") {
		t.Errorf("findings = %+v", got)
	}
}

// The check also runs on the address actually dialled, so a name that
// resolved public a moment ago and private now (rebinding), or a redirect to
// an internal host, is refused at connect time.
func TestTheDialerRefusesANonPublicAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, err = dialer(time.Second, nil, false).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "refused: address is not on the public internet") {
		t.Fatalf("dialled loopback: %v", err)
	}
	c, err := dialer(time.Second, nil, true).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("allowPrivate refused: %v", err)
	}
	_ = c.Close()
}

func TestAFetchOfAPrivateHostIsRefusedAndARedirectToAnOddPortIsNotFollowed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "http://127.0.0.1:8443/admin", http.StatusFound)
	}))
	defer srv.Close()
	if f := get(context.Background(), srv.URL+"/", time.Second, nil, false); f.OK() || !strings.Contains(f.Err, "refused") || hits != 0 {
		t.Fatalf("fetched a loopback server: %+v (hits %d)", f, hits)
	}
	f := get(context.Background(), srv.URL+"/", time.Second, nil, true)
	if !f.OK() || f.Status != http.StatusFound || strings.Contains(f.FinalURL, ":8443") || hits != 1 {
		t.Errorf("a redirect to port 8443 was followed or the fetch failed: %+v (hits %d)", f, hits)
	}
}

// One domain's crash is that domain's finding, not the run's.
func TestACrashingProbeIsOneDomainsFindingNotTheRuns(t *testing.T) {
	dns := fakeDNS{host: map[string][]string{"ok.example.com": {"93.184.216.34"}, "boom.example.com": {"93.184.216.34"}}}
	web := func(_ context.Context, host string) (Fetch, Fetch, Cert) {
		if host == "boom.example.com" {
			panic("slice bounds out of range")
		}
		return Fetch{Tried: true, Status: 200}, Fetch{Tried: true, Status: 301}, Cert{Checked: true, Verified: true}
	}
	p := Prober{Resolver: dns, Web: web, Concurrency: 2}
	res := p.Run(context.Background(), []Entry{{Name: "boom.example.com"}, {Name: "ok.example.com"}}, nil)
	if res[0].Fault == "" || !strings.Contains(res[0].Fault, "crashed") || res[1].Fault != "" || !res[1].Live() {
		t.Fatalf("results = %+v", res)
	}
	fs := Evaluate(res, nil, Options{Now: now})
	var seen bool
	for _, f := range fs {
		if f.Domain == "boom.example.com" && f.Area == "probe" && f.Sev == Medium {
			seen = true
		}
	}
	if !seen {
		t.Errorf("the crash is not in the report: %+v", fs)
	}
}

// A hostile MX can send forever; a hostile name can list hundreds of MX hosts.
func TestSMTPReadsAreCappedAndOnlyAFewMXHostsAreTried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "220-")
		for i := 0; i < 1<<20; i++ { // a megabyte of greeting, never finished
			if _, err := io.WriteString(c, strings.Repeat("A", 1024)); err != nil {
				return
			}
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := net.LookupPort("tcp", port)
	start := time.Now()
	r := NetSMTPProber(pn, 3*time.Second, nil, true)(context.Background(), host)
	if r.Err == "" || time.Since(start) > 2500*time.Millisecond {
		t.Errorf("an endless greeting was accepted or slow: %+v after %v", r, time.Since(start))
	}

	var probed []string
	c := newSMTPCache(func(_ context.Context, h string) SMTPResult {
		probed = append(probed, h)
		return SMTPResult{Checked: true, Host: h, Err: "connection refused"}
	})
	var hosts []string
	for i := 0; i < 200; i++ {
		hosts = append(hosts, "mx"+strings.Repeat("a", i%5+1)+string(rune('a'+i%26))+".example.com")
	}
	c.first(context.Background(), hosts, nil)
	if len(probed) != maxMXProbed {
		t.Errorf("probed %d MX hosts, want %d", len(probed), maxMXProbed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probed = nil
	newSMTPCache(c.probe).first(ctx, hosts, nil)
	if len(probed) != 0 {
		t.Errorf("a spent budget still probed %d host(s)", len(probed))
	}
}
