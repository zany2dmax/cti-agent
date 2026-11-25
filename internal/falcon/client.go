// Package falcon is a read-only client for the CrowdStrike Falcon API.
//
// # WHAT IT IS FOR
//
// Advisory triage (RUNBOOK 11k) judges a threat-intel item
// against facts from our own tools instead of a hand-written profile: which
// applications we run (Falcon Discover), which hosts have seen an indicator
// (IOC Management), and which ATT&CK techniques our detections have fired on
// (Alerts). This package is the transport for those lookups. Phase 1 uses it
// only for `cti-falcon --check`, which proves the API client's scopes before
// anything depends on them.
//
// # WHAT IT WILL NOT DO
//
//   - Write. It has GET for queries and nothing else; the API client the fleet
//     holds is created with Read scopes only, and this code could not use a
//     Write scope if one were granted by mistake.
//   - Talk to anything but a CrowdStrike API host. FALCON_BASE_URL is checked
//     against the published cloud hosts, so a typo in fleet.env cannot send
//     the client secret to another server.
//   - Log or print the token, the secret or a response body. Errors carry the
//     API's own error message, sanitised and shortened, and the HTTP status.
//     (Get returns the parsed response to its caller; what the caller prints
//     is the caller's rule - `--check` prints counts only.)
//
// Standard library only, like the rest of the module.
package falcon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zany2dmax/cti-agent/internal/httpx"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/useragent"
)

// clouds maps each CrowdStrike API host to the region name the API reports in
// its X-Cs-Region header. These are the only hosts the client will contact.
var clouds = map[string]string{
	"api.crowdstrike.com":            "us-1",
	"api.us-2.crowdstrike.com":       "us-2",
	"api.eu-1.crowdstrike.com":       "eu-1",
	"api.laggar.gcw.crowdstrike.com": "us-gov-1",
}

// hostForRegion is clouds reversed, for the "wrong cloud" hint.
func hostForRegion(region string) string {
	for h, r := range clouds {
		if r == region {
			return h
		}
	}
	return ""
}

// NormalizeBase accepts "api.us-2.crowdstrike.com" or
// "https://api.us-2.crowdstrike.com/" and returns "https://HOST". Anything
// that is not exactly one of the published API hosts over https - another
// scheme, a port, a path, a query, credentials in the URL, a look-alike host -
// is refused.
func NormalizeBase(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("FALCON_BASE_URL is empty")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("FALCON_BASE_URL %q is not a URL", safelog.Line(raw))
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("FALCON_BASE_URL must be https, not %q", safelog.Line(u.Scheme))
	}
	if u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("FALCON_BASE_URL must be just the API host, like https://api.us-2.crowdstrike.com")
	}
	host := strings.ToLower(u.Hostname())
	if _, ok := clouds[host]; !ok {
		return "", fmt.Errorf("FALCON_BASE_URL host %q is not a CrowdStrike API host (%s)",
			safelog.Line(host), knownHosts())
	}
	return "https://" + host, nil
}

func knownHosts() string {
	return "api.crowdstrike.com, api.us-2.crowdstrike.com, api.eu-1.crowdstrike.com, api.laggar.gcw.crowdstrike.com"
}

// Client is safe for concurrent use. The zero value is not usable: use New.
type Client struct {
	base     string // https://HOST, or a test server's URL
	clientID string
	secret   string
	http     *http.Client
	ua       string

	mu      sync.Mutex
	token   string
	tokExp  time.Time // renew after this: a minute before the real expiry
	tokTrue time.Time // the real expiry, for display

	// Seams for tests.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// New checks the base URL and returns a client. It makes no request.
func New(base, clientID, secret string) (*Client, error) {
	b, err := NormalizeBase(base)
	if err != nil {
		return nil, err
	}
	clientID, secret = strings.TrimSpace(clientID), strings.TrimSpace(secret)
	if clientID == "" || secret == "" {
		return nil, errors.New("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must both be set")
	}
	return newClient(b, clientID, secret, httpx.New(60*time.Second)), nil
}

// newClient skips the host check, for tests against httptest servers.
func newClient(base, clientID, secret string, hc *http.Client) *Client {
	// Redirects are refused: a 3xx would carry the bearer token to wherever
	// the Location header pointed.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		base: base, clientID: clientID, secret: secret, http: hc,
		ua:    useragent.String("cti-agent-fleet/cti-falcon"),
		now:   time.Now,
		sleep: sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Region is the cloud the base URL points at (us-1, us-2, eu-1, us-gov-1).
func (c *Client) Region() string {
	return clouds[strings.TrimPrefix(c.base, "https://")]
}

// Host is the API host, for display.
func (c *Client) Host() string { return strings.TrimPrefix(c.base, "https://") }

// maxBody caps every response read. A query of IDs at limit 500 is well
// under this; anything bigger is not something this client asked for.
const maxBody = 8 << 20

// APIError is one entry of the envelope's "errors" list.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Envelope is the shape every Falcon API response shares.
type Envelope struct {
	Meta struct {
		TraceID    string `json:"trace_id"`
		Pagination *struct {
			Total int    `json:"total"`
			After string `json:"after"`
		} `json:"pagination"`
	} `json:"meta"`
	Resources json.RawMessage `json:"resources"`
	Errors    []APIError      `json:"errors"`
}

// HTTPError is a non-2xx answer. Message is the API's own error text,
// sanitised; never the raw body.
type HTTPError struct {
	Status  int
	Path    string
	Message string
	Hint    string
	// FromAPI: the body was the API's own JSON envelope with a trace_id,
	// so the answer came from the Falcon service, not a gateway or proxy
	// in front of it.
	FromAPI bool
}

func (e *HTTPError) Error() string {
	s := fmt.Sprintf("falcon %s: HTTP %d", e.Path, e.Status)
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.Hint != "" {
		s += " (" + e.Hint + ")"
	}
	return s
}

// apiMessage pulls the error text out of a response body: the envelope's
// errors, or Falcon's token endpoint's {"errors":[...]} - never the raw body,
// which on a token call could echo the request.
func apiMessage(body []byte) string {
	var env Envelope
	if json.Unmarshal(body, &env) != nil || len(env.Errors) == 0 {
		return ""
	}
	return joinErrors(env.Errors)
}

// fromAPI reports whether body is the service's own envelope.
func fromAPI(body []byte) bool {
	var env Envelope
	return json.Unmarshal(body, &env) == nil && strings.TrimSpace(env.Meta.TraceID) != ""
}

func joinErrors(errs []APIError) string {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		if m := strings.TrimSpace(e.Message); m != "" {
			msgs = append(msgs, m)
		}
	}
	return safelog.LineMax(strings.Join(msgs, "; "), 300)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Token gets (or reuses) an OAuth2 client-credentials token. The token itself
// is never returned: callers only need to know that it worked, and when it
// expires.
func (c *Client) Token(ctx context.Context) (time.Time, error) {
	_, exp, err := c.currentToken(ctx)
	return exp, err
}

// currentToken returns the cached token, fetching one if needed, and its real
// expiry. The token is returned only inside the package.
func (c *Client) currentToken(ctx context.Context) (string, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || !c.now().Before(c.tokExp) {
		if err := c.fetchTokenLocked(ctx); err != nil {
			return "", time.Time{}, err
		}
	}
	return c.token, c.tokTrue, nil
}

// dropToken forgets tok after a 401, unless another caller already replaced
// it with a fresh one.
func (c *Client) dropToken(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == tok {
		c.token, c.tokExp, c.tokTrue = "", time.Time{}, time.Time{}
	}
}

func (c *Client) fetchTokenLocked(ctx context.Context) error {
	form := url.Values{"client_id": {c.clientID}, "client_secret": {c.secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		// Named so a token that never arrived (proxy, DNS, TLS) reads
		// differently from one that was refused.
		return fmt.Errorf("falcon token request failed: %w", scrubURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("falcon token response unreadable: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &HTTPError{Status: resp.StatusCode, Path: "/oauth2/token", Message: apiMessage(body)}
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			e.Hint = "redirected, not followed - check FALCON_BASE_URL is your cloud's API host"
		case resp.StatusCode == http.StatusUnauthorized:
			e.Hint = "the client ID or secret is wrong, or the API client was deleted"
		case resp.StatusCode == http.StatusForbidden:
			e.Hint = "the API client may restrict which IP addresses can use it"
		}
		if hint := c.regionHint(resp.Header.Get("X-Cs-Region")); hint != "" {
			e.Hint = hint
		}
		return e
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return errors.New("falcon token response had no access_token")
	}
	life := time.Duration(tr.ExpiresIn) * time.Second
	if life <= 0 {
		life = 30 * time.Minute
	}
	// Renew a minute early so a request never goes out on a token that
	// expires in flight.
	margin := time.Minute
	if life <= 2*margin {
		margin = life / 2
	}
	now := c.now()
	c.token = tr.AccessToken
	c.tokExp = now.Add(life - margin)
	c.tokTrue = now.Add(life)
	return nil
}

// regionHint names the right host when the API says the client belongs to a
// different cloud than FALCON_BASE_URL points at.
func (c *Client) regionHint(region string) string {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" || region == c.Region() {
		return ""
	}
	if h := hostForRegion(region); h != "" {
		return fmt.Sprintf("this API client is in %s - set FALCON_BASE_URL=https://%s", region, h)
	}
	return ""
}

// scrubURLError drops the URL from a transport error. The URL holds no secret
// (the secret is in the POST body), but keeping errors to "what failed" keeps
// them short and predictable.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Revoke ends the token early. Best effort: `--check` calls it so a probe does
// not leave a live token behind for its 30 minutes.
func (c *Client) Revoke(ctx context.Context) error {
	c.mu.Lock()
	tok := c.token
	c.token, c.tokExp, c.tokTrue = "", time.Time{}, time.Time{}
	c.mu.Unlock()
	if tok == "" {
		return nil
	}
	form := url.Values{"token": {tok}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/oauth2/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientID, c.secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("falcon token revoke failed: %w", scrubURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("falcon token revoke: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Response is a 2xx answer.
type Response struct {
	Status   int
	Envelope Envelope
}

// Total is meta.pagination.total, when the API sent one.
func (r *Response) Total() (int, bool) {
	if r.Envelope.Meta.Pagination == nil {
		return 0, false
	}
	return r.Envelope.Meta.Pagination.Total, true
}

const (
	getAttempts  = 3
	maxRetryWait = 2 * time.Minute
)

// Get runs one query. path is a fixed API route starting with "/"; every
// caller-supplied value goes in q, which is escaped. A 429 is retried after
// the API's X-Ratelimit-Retryafter, a 401 once with a fresh token.
func (c *Client) Get(ctx context.Context, path string, q url.Values) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("falcon: bad route %q", safelog.Line(path))
	}
	target := c.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	refreshed := false
	for attempt := 1; ; attempt++ {
		tok, _, err := c.currentToken(ctx)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, fmt.Errorf("falcon %s: bad request: %w", path, scrubURLError(err))
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.ua)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("falcon %s failed: %w", path, scrubURLError(err))
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, fmt.Errorf("falcon %s: response unreadable: %w", path, rerr)
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode <= 299:
			out := &Response{Status: resp.StatusCode}
			if err := json.Unmarshal(body, &out.Envelope); err != nil {
				return nil, fmt.Errorf("falcon %s: response is not JSON", path)
			}
			return out, nil
		case resp.StatusCode == http.StatusUnauthorized && !refreshed:
			// The token expired or was revoked between requests.
			refreshed = true
			c.dropToken(tok)
			continue
		case resp.StatusCode == http.StatusTooManyRequests && attempt < getAttempts:
			if err := c.sleep(ctx, retryWait(resp.Header.Get("X-Ratelimit-Retryafter"), attempt, c.now())); err != nil {
				return nil, err
			}
			continue
		}
		e := &HTTPError{Status: resp.StatusCode, Path: path, Message: apiMessage(body), FromAPI: fromAPI(body)}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			e.Hint = "redirected, not followed"
		}
		return nil, e
	}
}

// retryWait reads X-Ratelimit-Retryafter, a Unix time in seconds, capped at
// maxRetryWait; without it, 10s then 20s.
func retryWait(h string, attempt int, now time.Time) time.Duration {
	if n, err := strconv.ParseInt(strings.TrimSpace(h), 10, 64); err == nil {
		d := time.Unix(n, 0).Sub(now)
		if d < time.Second {
			d = time.Second
		}
		if d > maxRetryWait {
			d = maxRetryWait
		}
		return d
	}
	return time.Duration(attempt) * 10 * time.Second
}
