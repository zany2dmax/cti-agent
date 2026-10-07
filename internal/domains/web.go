package domains

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Web is what a host serves.
type Web struct {
	Host  string
	Addrs Lookup
	// CNAME is the canonical name when it differs from Host.
	CNAME string
	// Dangling: Host has a CNAME whose target does not resolve. Whoever can
	// claim that target - a deleted cloud app, a lapsed bucket name - serves
	// content as our domain. The classic subdomain takeover.
	Dangling bool

	HTTPS Fetch
	HTTP  Fetch
	TLS   Cert
}

// Fetch is one GET.
type Fetch struct {
	Tried    bool
	Status   int
	FinalURL string
	Err      string
	Title    string
	// Parked is the indicator that matched, "" when none did.
	Parked string
}

// OK reports whether the request produced a response at all.
func (f Fetch) OK() bool { return f.Tried && f.Err == "" && f.Status > 0 }

// Cert is the certificate the host presented on 443, judged separately from
// whether a page was served.
//
// The original checker fetched with certificate verification switched off and
// never looked again, so an expired or wrong-name certificate read as "live".
// Reachability and validity are different questions: the fetch below still
// skips verification so a broken certificate does not hide what the site
// serves, and this records whether the certificate would have passed.
type Cert struct {
	Checked   bool
	Verified  bool
	VerifyErr string
	NotAfter  time.Time
	Issuer    string
	DialErr   string
}

// Live reports whether the host answered on either port.
func (w Web) Live() bool { return w.HTTPS.OK() || w.HTTP.OK() }

// ParkedBy is the parking indicator from whichever fetch found one.
func (w Web) ParkedBy() string {
	if w.HTTPS.Parked != "" {
		return w.HTTPS.Parked
	}
	return w.HTTP.Parked
}

// parkedIndicators are matched against the final URL and the first 64 KiB of
// the page, lower-cased.
//
// Specific on purpose. The original list included wsimg.com and
// godaddysites.com, which are also what a real GoDaddy Website Builder site
// loads, so any live site built there read as parked. These are the parking
// and for-sale pages' own markers.
var parkedIndicators = []string{
	"/lander",
	"parking-lander",
	"parkingcrew",
	"sedoparking",
	"bodis.com",
	"parklogic",
	"domain is parked",
	"this domain is parked",
	"domain may be for sale",
	"buy this domain",
	"afternic.com",
	"dan.com/buy-domain",
	"hugedomains.com",
}

// WebProber fetches a host. A field so tests can replace the network.
type WebProber func(ctx context.Context, host string) (https, plain Fetch, cert Cert)

// ProbeWeb resolves host and, if it resolves, fetches it.
func ProbeWeb(ctx context.Context, r Resolver, fetch WebProber, host string) Web {
	w := Web{Host: host, Addrs: lookupHost(ctx, r, host)}
	if c, err := r.LookupCNAME(ctx, host); err == nil {
		if c = cleanHost(c); c != "" && c != host {
			w.CNAME = c
		}
	}
	if w.Addrs.Absent && w.CNAME != "" {
		w.Dangling = true
	}
	if !w.Addrs.Present() {
		return w
	}
	w.HTTPS, w.HTTP, w.TLS = fetch(ctx, host)
	return w
}

// NetWebProber is the real network.
func NetWebProber(timeout time.Duration) WebProber {
	return func(ctx context.Context, host string) (Fetch, Fetch, Cert) {
		return get(ctx, "https://"+host+"/", timeout), get(ctx, "http://"+host+"/", timeout),
			certOf(ctx, host, timeout)
	}
}

func get(ctx context.Context, url string, timeout time.Duration) Fetch {
	f := Fetch{Tried: true}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// #nosec G402 -- deliberate: this fetch measures what the host
			// serves, and a broken certificate must not hide that. Validity is
			// checked separately in certOf, with verification on.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			Proxy:                 nil,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f.Err = err.Error()
		return f
	}
	req.Header.Set("User-Agent", "cti-agent-domains/1 (weekly domain inventory check)")
	resp, err := client.Do(req)
	if err != nil {
		f.Err = shortNetErr(err)
		return f
	}
	defer func() { _ = resp.Body.Close() }()
	f.Status = resp.StatusCode
	f.FinalURL = resp.Request.URL.String()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	f.Title = title(body)
	f.Parked = parked(f.FinalURL, body)
	return f
}

func parked(finalURL string, body []byte) string {
	hay := strings.ToLower(finalURL + "\n" + string(body))
	for _, ind := range parkedIndicators {
		if strings.Contains(hay, ind) {
			return ind
		}
	}
	return ""
}

func title(body []byte) string {
	s := string(body)
	lo := strings.ToLower(s)
	i := strings.Index(lo, "<title")
	if i < 0 {
		return ""
	}
	j := strings.Index(lo[i:], ">")
	if j < 0 {
		return ""
	}
	start := i + j + 1
	end := strings.Index(lo[start:], "</title")
	if end < 0 {
		return ""
	}
	t := strings.Join(strings.Fields(s[start:start+end]), " ")
	if r := []rune(t); len(r) > 80 {
		t = string(r[:80]) + "..." // by rune: a title cut mid-character is invalid UTF-8
	}
	return t
}

// certOf dials 443 and verifies the chain against the system roots for host.
func certOf(ctx context.Context, host string, timeout time.Duration) Cert {
	c := Cert{Checked: true}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		// #nosec G402 -- the handshake must complete so the certificate can be
		// read; it is then verified explicitly below, with the result recorded.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12},
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		c.DialErr = shortNetErr(err)
		return c
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		c.DialErr = "not a TLS connection"
		return c
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		c.DialErr = "no certificate presented"
		return c
	}
	leaf := certs[0]
	c.NotAfter = leaf.NotAfter.UTC()
	c.Issuer = issuerName(leaf)
	inter := x509.NewCertPool()
	for _, ic := range certs[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		c.VerifyErr = verifyReason(err)
	} else {
		c.Verified = true
	}
	return c
}

func issuerName(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.CommonName
}

func verifyReason(err error) string {
	var h x509.HostnameError
	var inv x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &h):
		return "certificate is not valid for this name"
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return "certificate has expired"
	case errors.As(err, &inv):
		return "certificate is invalid: " + inv.Error()
	case errors.As(err, &ua):
		return "certificate is not from a trusted authority (self-signed or missing intermediate)"
	}
	return err.Error()
}

// shortNetErr keeps the useful tail of a net error: "connection refused",
// "i/o timeout", not the whole wrapped chain with addresses in it.
func shortNetErr(err error) string {
	s := err.Error()
	for _, k := range []string{"connection refused", "i/o timeout", "no such host",
		"connection reset", "network is unreachable", "context deadline exceeded",
		"handshake failure", "certificate", "EOF", "Client.Timeout"} {
		if strings.Contains(s, k) {
			if k == "Client.Timeout" || k == "context deadline exceeded" {
				return "timed out"
			}
			return k
		}
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
