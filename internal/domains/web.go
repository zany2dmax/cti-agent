package domains

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/zany2dmax/cti-agent/internal/useragent"
)

// Web is what a host serves.
type Web struct {
	Host  string
	Addrs Lookup
	// HasA / HasAAAA split Addrs by family, as the original checker reported.
	HasA, HasAAAA bool
	// CNAME is the canonical name when it differs from Host.
	CNAME string
	// Dangling: Host has a CNAME whose target does not resolve. Whoever can
	// claim that target - a deleted cloud app, a lapsed bucket name - serves
	// content as our domain. The classic subdomain takeover.
	Dangling bool

	// Private lists the addresses Host resolves to that are not public
	// (loopback, private, link-local, carrier-grade NAT, reserved). When it is
	// not empty the host was NOT fetched: see ProbeWeb.
	Private []string

	HTTPS Fetch
	HTTP  Fetch
	TLS   Cert
}

// Fetch is one GET.
type Fetch struct {
	Tried    bool
	Status   int
	FinalURL string
	Elapsed  time.Duration
	Err      string
	Title    string
	Server   string // the Server header, for the CSV
	HSTS     bool   // Strict-Transport-Security on the response
	// Parked is the parking or for-sale indicator that matched, "" when none.
	Parked string
	// Registrar is set when the page is served by the registrar's own hosting
	// (the original checker's GoDaddy indicators): a parked lander OR a
	// Website Builder site. Reported, not treated as parked - see below.
	Registrar string
}

// OK reports whether the request produced a response at all, of any status.
func (f Fetch) OK() bool { return f.Tried && f.Err == "" && f.Status > 0 }

// Serving is the original checker's "active": a 2xx or 3xx response. A 404 or
// a 503 answered, but it is not a working site.
func (f Fetch) Serving() bool { return f.OK() && f.Status >= 200 && f.Status <= 399 }

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
	Names     []string // the leaf's DNS names (SANs)
	DialErr   string
}

// Live is the original checker's "active": a 2xx/3xx on either scheme.
func (w Web) Live() bool { return w.HTTPS.Serving() || w.HTTP.Serving() }

// Answered reports whether anything responded at all, including error pages.
func (w Web) Answered() bool { return w.HTTPS.OK() || w.HTTP.OK() }

// Best is the fetch the report describes: HTTPS when it served, else HTTP,
// else whichever answered.
func (w Web) Best() Fetch {
	switch {
	case w.HTTPS.Serving():
		return w.HTTPS
	case w.HTTP.Serving():
		return w.HTTP
	case w.HTTPS.OK():
		return w.HTTPS
	}
	return w.HTTP
}

// RegistrarPage is the registrar-hosting indicator from either fetch.
func (w Web) RegistrarPage() string {
	if w.HTTPS.Registrar != "" {
		return w.HTTPS.Registrar
	}
	return w.HTTP.Registrar
}

// ParkedBy is the parking indicator from whichever fetch found one.
func (w Web) ParkedBy() string {
	if w.HTTPS.Parked != "" {
		return w.HTTPS.Parked
	}
	return w.HTTP.Parked
}

// parkedIndicators are matched against the final URL and the first 1 MiB of
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

// registrarIndicators are the original checker's GoDaddy markers, matched
// against the body, a handful of headers and the final URL host as it did.
//
// Kept, but as a SEPARATE signal from parked. They also match a real site
// built with GoDaddy Website Builder, which loads the same CDN; calling that
// parked would hide a live site from every web check. So a match is reported
// as "registrar-hosted", which is still worth knowing - nobody here may
// remember building it - and the strong indicators above decide "parked".
var registrarIndicators = []string{
	"godaddy",
	"wsimg.com",
	"secureservercdn.net",
	"godaddysites.com",
	"myftpupload.com",
}

// indicatorHeaders are the headers the original checker scanned.
var indicatorHeaders = []string{"Content-Security-Policy", "Link", "Set-Cookie",
	"Referrer-Policy", "Report-To", "Server"}

// WebProber fetches a host. A field so tests can replace the network.
type WebProber func(ctx context.Context, host string) (https, plain Fetch, cert Cert)

// ProbeWeb resolves host and, if it resolves, fetches it. A host that resolves
// to any non-public address is not fetched (see probeWeb).
func ProbeWeb(ctx context.Context, r Resolver, fetch WebProber, host string) Web {
	return probeWeb(ctx, r, fetch, host, false)
}

// probeWeb is ProbeWeb with the private-address policy given.
//
// WHY A HOST THAT RESOLVES PRIVATE IS NOT FETCHED. The names come from the
// inventory, but whoever controls a name's DNS chooses what it resolves to, so
// a fetch is a request this host makes at an address someone else picked: to
// loopback, to the network next door, to the cloud metadata address. The page
// title and Server header then land in a report. A name that points at a
// private address is also worth knowing about in itself (an internal record
// under a public name), so it is listed, not hidden. DOMAINS_ALLOW_PRIVATE=1
// restores fetching for an inventory that really has internal names.
func probeWeb(ctx context.Context, r Resolver, fetch WebProber, host string, allowPrivate bool) Web {
	w := Web{Host: host, Addrs: lookupHost(ctx, r, host)}
	for _, a := range w.Addrs.Values {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			w.HasA = true
		} else if ip != nil {
			w.HasAAAA = true
		}
	}
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
	if !allowPrivate {
		if priv := nonPublic(w.Addrs.Values); len(priv) > 0 {
			w.Private = priv
			return w
		}
	}
	w.HTTPS, w.HTTP, w.TLS = fetch(ctx, host)
	return w
}

// cgnat, benchmark, ietf and reserved are the ranges net.IP does not call
// private but that are not the public internet either.
var nonPublicNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8",      // "this" network
		"100.64.0.0/10",  // carrier-grade NAT
		"192.0.0.0/24",   // IETF protocol assignments
		"198.18.0.0/15",  // benchmarking
		"240.0.0.0/4",    // reserved
		"64:ff9b:1::/48", // local-use NAT64
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// publicIP reports whether ip is an address on the public internet: not
// loopback, private, link-local (which includes the cloud metadata address),
// multicast, unspecified, or in one of the reserved ranges above.
func publicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// nonPublic returns the entries of addrs that are not public addresses.
func nonPublic(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if !publicIP(net.ParseIP(a)) {
			out = append(out, a)
		}
	}
	return out
}

// dialer builds the dialer every probe uses. Unless allowPrivate is set its
// Control hook runs on the address actually being connected to - after DNS,
// for every connection including a redirect's and a rebinding answer's - and
// refuses a non-public one, so the check above cannot be raced.
func dialer(timeout time.Duration, res *net.Resolver, allowPrivate bool) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, Resolver: res}
	if !allowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if !publicIP(net.ParseIP(host)) {
				return errPrivateAddr
			}
			return nil
		}
	}
	return d
}

var errPrivateAddr = errors.New("refused: address is not on the public internet")

// NetWebProber is the real network.
//
// retries is how many times a request that got NO response is repeated. A
// response of any status is an answer and is never retried.
//
// res resolves the names it connects to - the same resolver the DNS checks
// use, so a site is fetched at the address the internet sees, not the one an
// internal DNS view hands this host. nil means the system resolver.
func NetWebProber(timeout time.Duration, retries int, res *net.Resolver, allowPrivate bool) WebProber {
	return func(ctx context.Context, host string) (Fetch, Fetch, Cert) {
		return getRetry(ctx, "https://"+host+"/", timeout, retries, res, allowPrivate),
			getRetry(ctx, "http://"+host+"/", timeout, retries, res, allowPrivate),
			certOf(ctx, host, timeout, res, allowPrivate)
	}
}

func getRetry(ctx context.Context, url string, timeout time.Duration, retries int, res *net.Resolver, allowPrivate bool) Fetch {
	f := get(ctx, url, timeout, res, allowPrivate)
	for i := 0; i < retries && !f.OK() && ctx.Err() == nil; i++ {
		f = get(ctx, url, timeout, res, allowPrivate)
	}
	return f
}

func get(ctx context.Context, url string, timeout time.Duration, res *net.Resolver, allowPrivate bool) Fetch {
	f := Fetch{Tried: true}
	start := time.Now()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// #nosec G402 -- deliberate: this fetch measures what the host
			// serves, and a broken certificate must not hide that. Validity is
			// checked separately in certOf, with verification on.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			Proxy:                 nil,
			DialContext:           dialer(timeout, res, allowPrivate).DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			// A redirect is the site's choice, so where it points is not ours
			// to follow anywhere: only the web's own ports. The last response
			// (the redirect itself) is what gets reported.
			if p := req.URL.Port(); p != "" && p != "80" && p != "443" {
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
	req.Header.Set("User-Agent", useragent.String("cti-agent-domains/1"))
	resp, err := client.Do(req)
	if err != nil {
		f.Err = shortNetErr(err)
		return f
	}
	defer func() { _ = resp.Body.Close() }()
	f.Status = resp.StatusCode
	f.FinalURL = resp.Request.URL.String()
	f.Server = resp.Header.Get("Server")
	f.HSTS = resp.Header.Get("Strict-Transport-Security") != ""
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	f.Elapsed = time.Since(start)
	f.Title = title(body)
	f.Parked = parked(f.FinalURL, body)
	var hdr strings.Builder
	for _, h := range indicatorHeaders {
		hdr.WriteString(resp.Header.Get(h))
		hdr.WriteString("\n")
	}
	f.Registrar = registrarHosted(resp.Request.URL.Host, hdr.String(), body)
	return f
}

// registrarHosted applies the original checker's indicators to the body, the
// headers it scanned, and the final URL host.
func registrarHosted(finalHost, headers string, body []byte) string {
	hay := strings.ToLower(finalHost + "\n" + headers + "\n" + string(body))
	for _, ind := range registrarIndicators {
		if strings.Contains(hay, ind) {
			return ind
		}
	}
	return ""
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

// title is the page's <title>, whitespace-collapsed and cut to 80 characters.
//
// Offsets are found on an ASCII-only lower-cased copy of the bytes, which is
// the same length as the original. strings.ToLower is not: some characters
// change length when lower-cased, so offsets taken from its result and applied
// to the original sliced out of range, and one such page crashed the whole
// weekly run.
func title(body []byte) string {
	lo := make([]byte, len(body))
	for i, b := range body {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		lo[i] = b
	}
	i := bytes.Index(lo, []byte("<title"))
	if i < 0 {
		return ""
	}
	j := bytes.IndexByte(lo[i:], '>')
	if j < 0 {
		return ""
	}
	start := i + j + 1
	end := bytes.Index(lo[start:], []byte("</title"))
	if end < 0 {
		return ""
	}
	t := strings.Join(strings.Fields(strings.ToValidUTF8(string(body[start:start+end]), "")), " ")
	if r := []rune(t); len(r) > 80 {
		t = string(r[:80]) + "..." // by rune: a title cut mid-character is invalid UTF-8
	}
	return t
}

// certOf dials 443 and verifies the chain against the system roots for host.
func certOf(ctx context.Context, host string, timeout time.Duration, res *net.Resolver, allowPrivate bool) Cert {
	c := Cert{Checked: true}
	d := &tls.Dialer{
		NetDialer: dialer(timeout, res, allowPrivate),
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
	c.Names = append([]string(nil), leaf.DNSNames...)
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
