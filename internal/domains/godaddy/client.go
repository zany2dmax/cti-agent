// Package godaddy lists the domains in a GoDaddy account.
//
// # READ-ONLY, AND IT NEVER ASKS FOR AN AUTH CODE
//
// One endpoint: GET /v1/domains. The credential is a Personal Access Token
// with domains.domain:read and nothing else. The API offers to include each
// domain's authCode in the listing - the secret that authorises a transfer
// to another registrar - and this client never requests it: a report, a log
// or a crash dump holding auth codes for every domain the organisation owns
// would be the most valuable file on the box.
//
// Checked against GoDaddy's published documentation and OpenAPI spec, not
// memory: Domains v1 declares Bearer (PAT) security, listing is limit/marker
// paginated up to 1000 a page, and the classic sso-key credential is being
// deprecated for Domains.
package godaddy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/domains"
)

// DefaultBaseURL is GoDaddy's production API. There is no separate read
// sandbox for an account's own domains.
const DefaultBaseURL = "https://api.godaddy.com"

const (
	pageSize = 1000
	// maxPages bounds the loop: 20,000 domains, far beyond this account. A
	// marker that stops advancing must end in an error, not a spin.
	maxPages = 20
)

// Client lists domains with a Personal Access Token.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New builds a client for the production API.
func New(token string) *Client {
	return &Client{BaseURL: DefaultBaseURL, Token: token,
		HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Name implements domains.Registrar.
func (c *Client) Name() string { return "godaddy" }

type wireDomain struct {
	Domain      string   `json:"domain"`
	Status      string   `json:"status"`
	Expires     string   `json:"expires"`
	RenewAuto   bool     `json:"renewAuto"`
	Locked      bool     `json:"locked"`
	Privacy     bool     `json:"privacy"`
	NameServers []string `json:"nameServers"`
}

// Domains returns every domain in the account, in any status.
//
// Any status, deliberately: CANCELLED or PENDING_TRANSFER is exactly what the
// weekly check needs to see, and filtering to ACTIVE would hide a domain on
// its way out of the account.
func (c *Client) Domains(ctx context.Context) ([]domains.Registration, error) {
	if strings.TrimSpace(c.Token) == "" {
		return nil, fmt.Errorf("godaddy: no token - set GODADDY_PAT in fleet.env")
	}
	var out []domains.Registration
	marker := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("godaddy: stopped after %d pages - either far more "+
				"domains than expected or the marker is not advancing; refusing to "+
				"return a partial list that would read as complete", maxPages)
		}
		rows, err := c.page(ctx, marker)
		if err != nil {
			return nil, err
		}
		for _, w := range rows {
			out = append(out, w.normalise())
		}
		if len(rows) < pageSize {
			return out, nil
		}
		next := rows[len(rows)-1].Domain
		if next == "" || next == marker {
			return nil, fmt.Errorf("godaddy: pagination did not advance past %q", marker)
		}
		marker = next
	}
}

func (c *Client) page(ctx context.Context, marker string) ([]wireDomain, error) {
	q := url.Values{}
	q.Set("limit", fmt.Sprint(pageSize))
	// nameServers ONLY. Never authCode - see the package comment.
	q.Set("includes", "nameServers")
	if marker != "" {
		q.Set("marker", marker)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.BaseURL, "/")+"/v1/domains?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("godaddy: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("godaddy: reading the response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp, body)
	}
	var rows []wireDomain
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("godaddy: response is not the expected JSON list: %w", err)
	}
	return rows, nil
}

// statusError says which of GoDaddy's refusals this is, because they need
// different fixes: a dead token, a token without the read scope, and an
// account that is not eligible all arrive as 401 or 403.
func statusError(resp *http.Response, body []byte) error {
	var env struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &env)
	detail := strings.TrimSpace(env.Code + " " + env.Message)
	if detail == "" {
		detail = strings.TrimSpace(string(body))
		if len(detail) > 200 {
			detail = detail[:200] + "..."
		}
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("godaddy: HTTP 401 - the token is missing, expired or revoked: %s", detail)
	case http.StatusForbidden:
		return fmt.Errorf("godaddy: HTTP 403 - the token lacks domains.domain:read, or the "+
			"account is not eligible (GoDaddy's code says which): %s", detail)
	case http.StatusTooManyRequests:
		return fmt.Errorf("godaddy: HTTP 429 - rate limited, retry after %s: %s",
			resp.Header.Get("Retry-After"), detail)
	}
	return fmt.Errorf("godaddy: HTTP %d: %s", resp.StatusCode, detail)
}

func (w wireDomain) normalise() domains.Registration {
	r := domains.Registration{
		Domain:      strings.TrimSuffix(strings.ToLower(strings.TrimSpace(w.Domain)), "."),
		Status:      strings.ToUpper(strings.TrimSpace(w.Status)),
		AutoRenew:   w.RenewAuto,
		Locked:      w.Locked,
		Privacy:     w.Privacy,
		NameServers: domains.CleanHosts(w.NameServers),
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(w.Expires)); err == nil {
		r.Expires = t.UTC()
	}
	return r
}
