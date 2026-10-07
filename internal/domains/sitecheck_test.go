package domains

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// The checks carried over from sitecheck.go, and the ones added beside them.

func TestMXHostMustResolve(t *testing.T) {
	r := goodSender()
	r.mx["example.com"] = []*net.MX{{Host: "mx.example-mail.test.", Pref: 10}, {Host: "old-mx.example-gone.test.", Pref: 20}}
	f := texts(run(t, r, okWeb("CA", now.AddDate(1, 0, 0)), []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	if !strings.Contains(f, "Medium example.com MX host old-mx.example-gone.test does not resolve") {
		t.Errorf("unresolvable MX not flagged:\n%s", f)
	}
}

func TestSMTPStartTLS(t *testing.T) {
	r := goodSender()
	var calls atomic.Int32
	p := Prober{Resolver: r, Web: okWeb("CA", now.AddDate(1, 0, 0)), Selectors: DefaultDKIMSelectors,
		SMTP: func(_ context.Context, host string) SMTPResult {
			calls.Add(1)
			return SMTPResult{Checked: true, Host: host, Port: 25, Banner: "220 mx ESMTP"}
		}}
	inv := []Entry{{Name: "example.com", Sends: true}, {Name: "news.example.com", Sends: true}}
	r.mx["news.example.com"] = []*net.MX{{Host: "mx.example-mail.test."}}
	cmp := Compare("godaddy", inv, []Registration{goodReg()})
	res := p.Run(context.Background(), inv, cmp.Covered)
	f := texts(Evaluate(res, &cmp, Options{Now: now}))
	if !strings.Contains(f, "MX mx.example-mail.test does not offer STARTTLS") {
		t.Errorf("missing STARTTLS not flagged:\n%s", f)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("one shared MX was dialled %d times, want once", n)
	}
}

func TestSMTPBlockedIsSaidOnce(t *testing.T) {
	var res []Result
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		res = append(res, Result{Entry: Entry{Name: d},
			Mail: Mail{SMTP: SMTPResult{Checked: true, Host: "mx." + d, Port: 25, Err: "timed out"}}})
	}
	if !SMTPBlocked(res) {
		t.Fatal("three timeouts and no success not read as blocked")
	}
	f := texts(Evaluate(res, nil, Options{Now: now, SMTPBlocked: true}))
	if strings.Contains(f, "did not answer on port") {
		t.Errorf("per-domain SMTP noise while blocked:\n%s", f)
	}
	res[0].Mail.SMTP.Err = ""
	if SMTPBlocked(res) {
		t.Error("one success still read as blocked")
	}
}

func TestDKIMKeyStrength(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r := goodSender()
	r.txt["selector1._domainkey.example.com"] = []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)}
	f := texts(run(t, r, okWeb("CA", now.AddDate(1, 0, 0)), []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	if !strings.Contains(f, "Medium example.com DKIM key at selector1 is 1024-bit RSA; rotate to 2048") {
		t.Errorf("1024-bit key not flagged:\n%s", f)
	}
}

func TestStatusRedirectAndRegistrar(t *testing.T) {
	r := goodSender()
	web := func(_ context.Context, host string) (Fetch, Fetch, Cert) {
		if strings.HasPrefix(host, "www.") {
			return Fetch{Tried: true, Status: 200, FinalURL: "https://shop.example-elsewhere.test/"},
				Fetch{Tried: true, Status: 200, FinalURL: "http://" + host + "/"},
				Cert{Checked: true, Verified: true, NotAfter: now.AddDate(1, 0, 0)}
		}
		return Fetch{Tried: true, Status: 503}, Fetch{Tried: true, Status: 503}, Cert{Checked: true, Verified: true, NotAfter: now.AddDate(1, 0, 0)}
	}
	f := texts(run(t, r, web, []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	for _, want := range []string{
		"Medium example.com returns HTTP 503",
		"www.example.com: redirects to shop.example-elsewhere.test, which is not one of our domains",
		"www.example.com: http:// serves the page instead of redirecting to https://",
	} {
		if !strings.Contains(f, want) {
			t.Errorf("missing %q in:\n%s", want, f)
		}
	}

	// A Website Builder page is registrar-hosted, NOT parked: it is live.
	if g := registrarHosted("example.com", "", []byte(`<script src="https://img1.wsimg.com/x.js">`)); g != "wsimg.com" {
		t.Errorf("registrar indicator not matched: %q", g)
	}
	if registrarHosted("example.com", "Server: nginx", []byte("<h1>ours</h1>")) != "" {
		t.Error("an ordinary page read as registrar-hosted")
	}
}

func TestCSVKeepsSitecheckColumnsAndDefusesFormulas(t *testing.T) {
	res := []Result{{
		Entry: Entry{Name: "example.com", Sends: true},
		Web: []Web{{Host: "example.com", Addrs: Lookup{Values: []string{"192.0.2.1", "2001:db8::1"}},
			HasA: true, HasAAAA: true,
			HTTPS: Fetch{Tried: true, Status: 200, FinalURL: "https://example.com/", Title: "=HYPERLINK(\"x\")"}}},
		Mail: Mail{MX: Lookup{Values: []string{"mx.example-mail.test"}}},
	}}
	rows, err := csv.NewReader(bytes.NewReader(CSV(res))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	old := []string{"domain", "dns_ok", "has_a", "has_aaaa", "cname", "has_mx", "mx_hosts",
		"has_spf", "spf_record", "has_dmarc", "dmarc_record", "has_dkim", "dkim_selectors",
		"dkim_records", "smtp_checked", "smtp_host", "smtp_port", "smtp_banner", "scheme",
		"status", "active", "final_url", "response_time_ms", "tls_server_name", "tls_issuer",
		"error", "excluded_parked", "email_check_note"}
	for i, c := range old {
		if rows[0][i] != c {
			t.Fatalf("column %d = %q, want sitecheck's %q", i, rows[0][i], c)
		}
	}
	if len(rows[1]) != len(rows[0]) {
		t.Fatalf("row has %d cells, header %d", len(rows[1]), len(rows[0]))
	}
	col := func(name string) string {
		for i, c := range rows[0] {
			if c == name {
				return rows[1][i]
			}
		}
		t.Fatalf("no column %s", name)
		return ""
	}
	if col("has_a") != "true" || col("has_aaaa") != "true" || col("active") != "true" || col("scheme") != "https" {
		t.Errorf("row = %v", rows[1])
	}
	if !strings.HasPrefix(col("title"), "'=") {
		t.Errorf("formula not defused: %q", col("title"))
	}
}
