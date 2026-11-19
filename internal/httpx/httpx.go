// Package httpx is the one way the fleet's Go code builds an HTTP client.
//
// Every command that sends a credential (Graph, Jira, Qualys, Falcon,
// GoDaddy) used to build its own http.Client from the defaults. That left two
// gaps: no TLS floor, and nothing stopping a mistyped or hostile base URL
// (QUALYS_BASE_URL=http://..., a redirect that downgrades) from carrying a
// Basic or Bearer credential over plaintext HTTP. This package closes both in
// one place:
//
//   - TLS 1.2 is the minimum version.
//   - A request to anything but https:// is refused BEFORE it is sent, so the
//     Authorization header the caller already attached never leaves the
//     process. The one exception is a loopback address (localhost, 127.0.0.1,
//     ::1), so tests against httptest servers still work; a loopback address
//     is not a network path.
//   - A redirect to anything but https:// is refused, and a chain stops after
//     ten hops.
//
// A repo test (TestNoClientBypassesHTTPX) fails when a new http.Client{ is
// built anywhere else without a reason on the allowlist.
package httpx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MinTLS is the lowest TLS version any fleet client will negotiate.
const MinTLS = tls.VersionTLS12

const maxRedirects = 10

// Transport is the default transport with the TLS floor set. Callers that
// need their own timeouts (the Qualys limiter) start from this and then wrap
// it with Guard.
func Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: MinTLS}
	return t
}

// New is an http.Client with the TLS floor, the HTTPS-only guard and the
// HTTPS-only redirect rule.
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     Guard(Transport()),
		CheckRedirect: CheckRedirect,
	}
}

// Guard wraps a RoundTripper so that a request to anything but https:// (or a
// loopback address) fails before it is sent. A nil base means Transport().
func Guard(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = Transport()
	}
	return guard{base}
}

type guard struct{ base http.RoundTripper }

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := Check(req.URL); err != nil {
		// The body of a request that is never sent still has to be closed.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return g.base.RoundTrip(req)
}

// Check says whether the fleet may send a request to u: https, or loopback.
// The error this returns names the host and not the path or query. Note that
// http.Client wraps it in a *url.Error carrying the full request URL, so a
// caller that logs the wrapped error must not put a secret in the URL.
func Check(u *url.URL) error {
	if u == nil {
		return errors.New("httpx: no URL")
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") && Loopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("httpx: refusing a %s:// request to %s: credentials and data go over https only (check the base URL in fleet.env)",
		strings.ToLower(u.Scheme), u.Host)
}

// CheckRedirect is the http.Client.CheckRedirect for every fleet client. Go
// drops Authorization on a redirect to another host, but not on a same-host
// downgrade to http; this refuses both.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if err := Check(req.URL); err != nil {
		return err
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("httpx: stopped after %d redirects", maxRedirects)
	}
	return nil
}

// Loopback reports whether host is localhost or a loopback IP.
func Loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
