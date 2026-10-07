package domains

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDNS is a zone in a map. A name with no entry for a type is NXDOMAIN;
// a name in fail is a SERVFAIL-style error.
type fakeDNS struct {
	host  map[string][]string
	cname map[string]string
	mx    map[string][]*net.MX
	txt   map[string][]string
	ns    map[string][]*net.NS
	fail  map[string]bool
}

func nx(name string) error { return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true} }

func (f fakeDNS) err(name string) error {
	if f.fail[name] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return nil
}

func (f fakeDNS) LookupHost(_ context.Context, h string) ([]string, error) {
	if err := f.err(h); err != nil {
		return nil, err
	}
	if v, ok := f.host[h]; ok {
		return v, nil
	}
	return nil, nx(h)
}
func (f fakeDNS) LookupCNAME(_ context.Context, h string) (string, error) {
	if v, ok := f.cname[h]; ok {
		return v + ".", nil
	}
	return h + ".", nil
}
func (f fakeDNS) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	if err := f.err(n); err != nil {
		return nil, err
	}
	if v, ok := f.mx[n]; ok {
		return v, nil
	}
	return nil, nx(n)
}
func (f fakeDNS) LookupTXT(_ context.Context, n string) ([]string, error) {
	if err := f.err(n); err != nil {
		return nil, err
	}
	if v, ok := f.txt[n]; ok {
		return v, nil
	}
	return nil, nx(n)
}
func (f fakeDNS) LookupNS(_ context.Context, n string) ([]*net.NS, error) {
	if v, ok := f.ns[n]; ok {
		return v, nil
	}
	return nil, nx(n)
}

var now = time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)

func okWeb(issuer string, notAfter time.Time) WebProber {
	return func(context.Context, string) (Fetch, Fetch, Cert) {
		return Fetch{Tried: true, Status: 200}, Fetch{Tried: true, Status: 301},
			Cert{Checked: true, Verified: true, Issuer: issuer, NotAfter: notAfter}
	}
}

func texts(f []Finding) string {
	var b strings.Builder
	for _, x := range f {
		b.WriteString(x.Sev.String() + " " + x.Domain + " " + x.Text + "\n")
	}
	return b.String()
}

func TestLookupDistinguishesAbsentFromFailed(t *testing.T) {
	r := fakeDNS{fail: map[string]bool{"_dmarc.broken.example": true}}
	if l := lookupTXT(context.Background(), r, "_dmarc.missing.example"); !l.Absent || !l.Known() {
		t.Errorf("NXDOMAIN = %+v, want Absent", l)
	}
	if l := lookupTXT(context.Background(), r, "_dmarc.broken.example"); l.Known() || l.Absent {
		t.Errorf("SERVFAIL = %+v, want an error, not absent", l)
	}
	// And the evaluation must not call a failed lookup "no DMARC".
	m := ProbeMail(context.Background(), r, "broken.example", "", nil)
	f := texts(Evaluate([]Result{{Entry: Entry{Name: "broken.example", Sends: true}, Mail: m}}, nil, Options{Now: now}))
	if strings.Contains(f, "no DMARC record") || !strings.Contains(f, "DMARC lookup failed") {
		t.Errorf("failed lookup reported as absence:\n%s", f)
	}
}

func goodSender() fakeDNS {
	return fakeDNS{
		host: map[string][]string{"example.com": {"192.0.2.1"}, "www.example.com": {"192.0.2.1"},
			"mx.example-mail.test": {"192.0.2.25"}},
		mx: map[string][]*net.MX{"example.com": {{Host: "mx.example-mail.test.", Pref: 10}}},
		txt: map[string][]string{
			"example.com":                      {"some-verification=abc", "v=spf1 include:_spf.example-mail.test -all"},
			"_spf.example-mail.test":           {"v=spf1 ip4:192.0.2.0/24 -all"},
			"_dmarc.example.com":               {"v=DMARC1; p=reject; rua=mailto:dmarc@example-reports.test"},
			"selector1._domainkey.example.com": {"v=DKIM1; k=rsa; p=MIIBIjAN"},
		},
		ns: map[string][]*net.NS{"example.com": {{Host: "ns1.example-dns.test."}, {Host: "ns2.example-dns.test."}}},
	}
}

func run(t *testing.T, r fakeDNS, w WebProber, inv []Entry, regs []Registration) []Finding {
	t.Helper()
	cmp := Compare("godaddy", inv, regs)
	orgOf := map[string]Registration{}
	for k, v := range cmp.Covered {
		orgOf[k] = v
	}
	res := Prober{Resolver: r, Web: w, Selectors: DefaultDKIMSelectors}.Run(context.Background(), inv, orgOf)
	return Evaluate(res, &cmp, Options{Now: now, Registrar: "godaddy"})
}

func goodReg() Registration {
	return Registration{Domain: "example.com", Status: "ACTIVE", Expires: now.AddDate(1, 0, 0),
		AutoRenew: true, Locked: true, NameServers: []string{"ns1.example-dns.test", "ns2.example-dns.test"}}
}

func TestGoodSenderHasNoFindings(t *testing.T) {
	f := run(t, goodSender(), okWeb("Example CA", now.AddDate(0, 3, 0)),
		[]Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()})
	if len(f) != 0 {
		t.Errorf("a correctly configured sender produced findings:\n%s", texts(f))
	}
}

func TestSenderFaults(t *testing.T) {
	r := goodSender()
	r.txt["example.com"] = []string{"v=spf1 include:a.test", "v=spf1 -all"}
	r.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=none"}
	delete(r.txt, "selector1._domainkey.example.com")
	reg := goodReg()
	reg.Locked, reg.AutoRenew = false, false
	reg.Expires = now.AddDate(0, 0, 20)
	reg.NameServers = []string{"ns1.other-dns.test", "ns2.other-dns.test"}
	f := texts(run(t, r, okWeb("Example CA", now.AddDate(0, 0, 10)),
		[]Entry{{Name: "example.com", Sends: true}}, []Registration{reg}))
	for _, want := range []string{
		"High example.com 2 SPF records",
		"High example.com registration expires in 20 days",
		"High example.com transfer lock is OFF",
		"High example.com www.example.com: certificate expires in 10 days",
		"Medium example.com DMARC policy is none",
		"Medium example.com DMARC has no rua=",
		"Medium example.com no DKIM key at the selectors tried",
		"Medium example.com DNS reports nameservers",
	} {
		if !strings.Contains(f, want) {
			t.Errorf("missing %q in:\n%s", want, f)
		}
	}
}

func TestSPFLookupLimit(t *testing.T) {
	r := goodSender()
	var inc []string
	for i := 0; i < 11; i++ {
		n := "i" + string(rune('a'+i)) + ".test"
		inc = append(inc, "include:"+n)
		r.txt[n] = []string{"v=spf1 ip4:192.0.2.1 -all"}
	}
	r.txt["example.com"] = []string{"v=spf1 " + strings.Join(inc, " ") + " -all"}
	f := texts(run(t, r, okWeb("CA", now.AddDate(1, 0, 0)), []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	if !strings.Contains(f, "SPF needs 11 DNS lookups") {
		t.Errorf("lookup limit not flagged:\n%s", f)
	}
	// Self-include terminates.
	r.txt["example.com"] = []string{"v=spf1 include:example.com -all"}
	_ = run(t, r, okWeb("CA", now.AddDate(1, 0, 0)), []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()})
}

func TestNonSender(t *testing.T) {
	locked := fakeDNS{txt: map[string][]string{
		"example.net":        {"v=spf1 -all"},
		"_dmarc.example.net": {"v=DMARC1; p=reject"},
	}}
	f := run(t, locked, okWeb("CA", now), []Entry{{Name: "example.net"}}, nil)
	for _, x := range f {
		if x.Area == "mail" {
			t.Errorf("locked-down non-sender flagged: %s", x.Text)
		}
	}

	leaky := fakeDNS{txt: map[string][]string{
		"example.net":                      {"v=spf1 include:_spf.example-mail.test ~all"},
		"selector1._domainkey.example.net": {"v=DKIM1; p=MIIB"},
		"_dmarc.example.net":               {"v=DMARC1; p=quarantine"},
	}}
	s := texts(run(t, leaky, okWeb("CA", now), []Entry{{Name: "example.net"}}, nil))
	for _, want := range []string{"SPF authorises senders", "publishes DKIM keys", "should be p=reject",
		"not in the godaddy account"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestSubdomainInheritsDMARC(t *testing.T) {
	r := goodSender()
	r.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=reject; sp=none; rua=mailto:x@example-reports.test"}
	r.txt["news.example.com"] = []string{"v=spf1 include:_spf.example-mail.test -all"}
	r.txt["selector1._domainkey.news.example.com"] = []string{"v=DKIM1; p=MIIB"}
	r.mx["news.example.com"] = []*net.MX{{Host: "mx.example-mail.test."}}
	f := texts(run(t, r, okWeb("CA", now.AddDate(1, 0, 0)),
		[]Entry{{Name: "example.com", Sends: true}, {Name: "news.example.com", Sends: true}}, []Registration{goodReg()}))
	if strings.Contains(f, "news.example.com no DMARC") {
		t.Errorf("subdomain covered by its parent's record reported as missing DMARC:\n%s", f)
	}
	if !strings.Contains(f, "news.example.com DMARC policy is none (inherited from example.com)") {
		t.Errorf("sp=none on the parent not applied to the subdomain:\n%s", f)
	}
}

func TestDanglingCNAME(t *testing.T) {
	r := fakeDNS{cname: map[string]string{"old.example.com": "gone-app.example-cloud.test"}}
	f := texts(run(t, r, okWeb("CA", now), []Entry{{Name: "old.example.com"}}, []Registration{goodReg()}))
	if !strings.Contains(f, "High old.example.com CNAME points at gone-app.example-cloud.test") {
		t.Errorf("dangling CNAME not flagged:\n%s", f)
	}
}

func TestWebStates(t *testing.T) {
	r := goodSender()
	bad := func(context.Context, string) (Fetch, Fetch, Cert) {
		return Fetch{Tried: true, Status: 200}, Fetch{Tried: true, Status: 200},
			Cert{Checked: true, VerifyErr: "certificate is not valid for this name"}
	}
	f := texts(run(t, r, bad, []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	if !strings.Contains(f, "High example.com serves a page with a certificate browsers reject") {
		t.Errorf("invalid certificate on a live page not flagged:\n%s", f)
	}
	parkedWeb := func(context.Context, string) (Fetch, Fetch, Cert) {
		return Fetch{Tried: true, Status: 200, Parked: "/lander"}, Fetch{}, Cert{Checked: true, VerifyErr: "x"}
	}
	f = texts(run(t, r, parkedWeb, []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	if strings.Contains(f, "certificate") {
		t.Errorf("a parked page's certificate raised a finding:\n%s", f)
	}
	httpOnly := func(context.Context, string) (Fetch, Fetch, Cert) {
		return Fetch{Tried: true, Err: "connection refused"}, Fetch{Tried: true, Status: 200},
			Cert{Checked: true, DialErr: "connection refused"}
	}
	f = texts(run(t, r, httpOnly, []Entry{{Name: "example.com", Sends: true}}, []Registration{goodReg()}))
	if !strings.Contains(f, "HTTP only") {
		t.Errorf("HTTP-only not flagged:\n%s", f)
	}
}

func TestParkedIndicatorsAreSpecific(t *testing.T) {
	// A real Website Builder site loads assets from these; it is not parked.
	if p := parked("https://example.com/", []byte(`<img src="https://img1.wsimg.com/x.png">`)); p != "" {
		t.Errorf("builder-hosted site read as parked by %q", p)
	}
	if p := parked("https://example.com/lander", nil); p != "/lander" {
		t.Errorf("lander redirect not detected: %q", p)
	}
}

func TestDiff(t *testing.T) {
	r := goodSender()
	inv := []Entry{{Name: "example.com", Sends: true}}
	regs := []Registration{goodReg(), {Domain: "spare.example", Status: "ACTIVE", Locked: true, AutoRenew: true}}
	cmp := Compare("godaddy", inv, regs)
	res := Prober{Resolver: r, Web: okWeb("CA One", now.AddDate(1, 0, 0))}.Run(context.Background(), inv, cmp.Covered)
	week1 := Snap(now, res, &cmp, regs, nil)

	if d := Diff(nil, week1, true, "godaddy"); d != nil {
		t.Errorf("first run produced changes: %v", d)
	}
	if d := Diff(week1, Snap(now, res, &cmp, regs, week1), true, "godaddy"); len(d) != 0 {
		t.Errorf("unchanged week produced changes:\n%s", texts(d))
	}

	// Week 2: MX lookup fails (must NOT read as removed), NS changes, a
	// registration disappears, lock switched off.
	failing := fakeDNS{host: r.host, cname: r.cname, txt: r.txt,
		ns: map[string][]*net.NS{"example.com": {{Host: "ns1.evil-dns.test."}}}}
	failMX := mxFails{failing}
	reg2 := goodReg()
	reg2.Locked = false
	regs2 := []Registration{reg2}
	cmp2 := Compare("godaddy", inv, regs2)
	res2 := Prober{Resolver: failMX, Web: okWeb("CA One", now.AddDate(1, 0, 0))}.Run(context.Background(), inv, cmp2.Covered)
	week2 := Snap(now.AddDate(0, 0, 7), res2, &cmp2, regs2, week1)
	d := texts(Diff(week1, week2, true, "godaddy"))
	for _, want := range []string{
		"High example.com nameservers changed",
		"High example.com transfer lock was switched OFF",
		"High spare.example no longer in the godaddy account",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("missing %q in:\n%s", want, d)
		}
	}
	if strings.Contains(d, "MX") {
		t.Errorf("a failed MX lookup was reported as a change:\n%s", d)
	}
	if week2.Domains["example.com"].MX != week1.Domains["example.com"].MX {
		t.Errorf("failed lookup did not carry last week's MX forward")
	}

	// Registrar skipped this week: nothing "left the account".
	week3 := Snap(now, res2, nil, nil, week2)
	if d := texts(Diff(week2, week3, false, "godaddy")); strings.Contains(d, "no longer in") {
		t.Errorf("skipped registrar read as domains leaving:\n%s", d)
	}
}

// mxFails wraps a resolver so every MX lookup is a server failure.
type mxFails struct{ fakeDNS }

func (m mxFails) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
}

func TestClassifyPlainError(t *testing.T) {
	if l := classify(errors.New("boom")); l.Known() {
		t.Errorf("a non-DNS error read as an answer: %+v", l)
	}
}
