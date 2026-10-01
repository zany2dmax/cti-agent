package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client talks to Jira Cloud's REST API v2.
//
// # WHY v2 AND NOT v3
//
// v3 requires the description field as an Atlassian Document Format document -
// a nested JSON tree of paragraph, table and tableRow nodes. Building that by
// hand for every ticket is a lot of code whose only job is to express a table
// and a list, and every bug in it is a malformed ticket. v2 accepts wiki
// markup as a plain string, which is what Description() produces. v2 is not
// deprecated for Jira Cloud; it is the older of two supported versions.
//
// # AUTH
//
// Basic auth with email and an API token, which is what Atlassian documents
// for Jira Cloud server-to-server calls. The token is a bearer-equivalent
// secret: it carries the full permissions of the account it belongs to, so the
// account behind JIRA_EMAIL should be one that can create issues in the
// allowlisted project and little else. See SECURITY.md.
type Client struct {
	BaseURL string // https://crhomeusa.atlassian.net
	Email   string
	Token   string
	HTTP    *http.Client
}

// New builds a client with a timeout that is bounded but generous: attachment
// uploads are slower than JSON calls and a ticket half-filed is worse than one
// that took a while.
func New(baseURL, email, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Email:   email,
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) authHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Email+":"+c.Token))
}

// IssueRequest is a create payload.
type IssueRequest struct {
	ProjectKey  string
	IssueType   string
	Summary     string
	Description string
	Labels      []string
}

// IssueResult identifies a created or found issue.
type IssueResult struct {
	Key  string `json:"key"`
	ID   string `json:"id"`
	Self string `json:"self"`
}

// BrowseURL is the link a human clicks. Built from BaseURL rather than from
// the API's "self" field, which points at the REST endpoint and is useless in
// an email.
func (c *Client) BrowseURL(key string) string {
	return c.BaseURL + "/browse/" + url.PathEscape(key)
}

// CreateIssue files a new issue and returns its key.
func (c *Client) CreateIssue(ctx context.Context, r IssueRequest) (IssueResult, error) {
	body := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": r.ProjectKey},
			"issuetype":   map[string]string{"name": r.IssueType},
			"summary":     r.Summary,
			"description": r.Description,
			"labels":      r.Labels,
		},
	}
	var out IssueResult
	if err := c.do(ctx, http.MethodPost, "/rest/api/2/issue", body, &out); err != nil {
		return IssueResult{}, err
	}
	if out.Key == "" {
		return IssueResult{}, fmt.Errorf("jira accepted the create but returned no issue key")
	}
	return out, nil
}

// Search runs a JQL query and returns the matching issues.
//
// # /rest/api/3/search/jql, NOT /rest/api/2/search
//
// The old endpoint is GONE - not deprecated, removed. It answers HTTP 410:
//
//	The requested API has been removed. Please migrate to the
//	/rest/api/3/search/jql API.
//
// Found by running it against the live tenant, which is the only way this
// class of fault is ever found: it cannot fail in a stub, and the code was
// correct on the day it was written.
//
// THIS IS WHY THE REST OF THE CLIENT IS ON v2 AND THIS CALL IS NOT. Mixing
// versions looks like an oversight, so to be explicit: creating an issue on
// v3 requires the description as an Atlassian Document Format tree, which is
// a pile of nested JSON whose only job is a table and a list. Search has no
// description, so it costs nothing to move and everything to leave broken.
// Each call uses the oldest version that still works and does not force ADF.
//
// The new endpoint differs in three ways that matter:
//
//   - Fields must be requested EXPLICITLY. It returns only the issue id by
//     default, so a caller that worked by accident on the old endpoint gets
//     empty summaries and an empty status here - which would make IsDone
//     report every ticket as not-done, and the duplicate check would still
//     work while the status logic quietly stopped.
//   - Pagination is by nextPageToken, not startAt. There is no total.
//   - isLast says whether more pages exist.
//
// Only the first page is read. Duplicate detection asks "does one exist", and
// the answer does not change on page two - but the paging fields are parsed
// rather than ignored so that a future caller that does need them finds them
// already there.
func (c *Client) Search(ctx context.Context, jql string, max int) ([]Issue, error) {
	if max <= 0 {
		max = 5
	}
	body := map[string]any{
		"jql":        jql,
		"maxResults": max,
		// Named explicitly. The new endpoint does NOT default to a useful set.
		"fields": []string{"summary", "status", "labels", "created"},
	}
	var out SearchPage
	if err := c.do(ctx, http.MethodPost, "/rest/api/3/search/jql", body, &out); err != nil {
		return nil, err
	}
	return out.Issues, nil
}

// SearchPage is one page of the token-paginated search response.
type SearchPage struct {
	Issues        []Issue `json:"issues"`
	NextPageToken string  `json:"nextPageToken,omitempty"`
	IsLast        bool    `json:"isLast"`
}

// Issue is the subset of an issue this package reads.
type Issue struct {
	Key    string `json:"key"`
	Fields struct {
		Summary string `json:"summary"`
		Status  struct {
			Name string `json:"name"`
			// StatusCategory is what "is it done" should be read from. The
			// status NAME is per-project and renamed freely - "Done",
			// "Closed", "Resolved", "Completed" - so matching on it means the
			// fleet's idea of finished depends on a workflow someone can edit.
			// The category key is one of new / indeterminate / done.
			StatusCategory struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"statusCategory"`
		} `json:"status"`
		Labels  []string `json:"labels"`
		Created string   `json:"created"`
	} `json:"fields"`
}

// IsDone reports whether the issue has reached a done-category status.
func (i Issue) IsDone() bool { return i.Fields.Status.StatusCategory.Key == "done" }

// AddComment appends a comment. Used to note a changed host count on a ticket
// that already exists, rather than filing a second one.
func (c *Client) AddComment(ctx context.Context, key, text string) error {
	body := map[string]any{"body": text}
	path := "/rest/api/2/issue/" + url.PathEscape(key) + "/comment"
	return c.do(ctx, http.MethodPost, path, body, nil)
}

// Attach uploads a file to an issue.
//
// Two things here are non-obvious and both are required by Jira:
//
//   - X-Atlassian-Token: no-check. Without it the request is rejected as XSRF.
//     This is Atlassian's documented opt-out for programmatic uploads, and it
//     is the single most common reason an attachment upload 403s while every
//     other call on the same token succeeds.
//   - multipart/form-data with the field named exactly "file". Not "files",
//     not the filename.
func (c *Client) Attach(ctx context.Context, key, name string, content []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		return fmt.Errorf("building the attachment form: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return fmt.Errorf("writing attachment %q: %w", name, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing the attachment form: %w", err)
	}

	path := c.BaseURL + "/rest/api/2/issue/" + url.PathEscape(key) + "/attachments"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, &buf)
	if err != nil {
		return fmt.Errorf("building the attachment request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Atlassian-Token", "no-check")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("uploading attachment to %s: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return checkStatus(resp, "attach "+name+" to "+key)
}

// do issues a JSON request. out may be nil for calls whose body is ignored.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding the %s request: %w", path, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return fmt.Errorf("building the %s request: %w", path, err)
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkStatus(resp, method+" "+path); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding the %s response: %w", path, err)
	}
	return nil
}

// maxErrorBody bounds what an error page can push into a log line. A Jira
// error can be an HTML page when a proxy intercepts the call, and the whole of
// it in the journal is not a diagnosis.
const maxErrorBody = 2000

// checkStatus turns a non-2xx into an error that names what Jira objected to.
//
// Jira reports field validation failures as a 400 with errorMessages and a
// per-field errors map, and that map is the entire diagnosis: "issuetype: Task
// is not valid for project CR" is actionable, "jira returned 400" is not.
func checkStatus(resp *http.Response, what string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))

	// 410 means Atlassian retired the endpoint, which is a different problem
	// from a bad request and needs a different person: nobody can fix it in
	// fleet.env. Qualys did exactly this to the 2.0 KnowledgeBase, and the
	// lesson was that an EOL reads like a transient failure until something
	// says the word. Jira puts the replacement path in the body, so the body
	// is preserved verbatim below.
	if resp.StatusCode == http.StatusGone {
		return fmt.Errorf("%s failed: THIS ENDPOINT HAS BEEN REMOVED by Atlassian "+
			"(HTTP 410) - this needs a code change, not a config change: %s",
			what, strings.TrimSpace(string(raw)))
	}

	var parsed struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
	}
	if json.Unmarshal(raw, &parsed) == nil {
		var parts []string
		parts = append(parts, parsed.ErrorMessages...)
		// Sorted: the field errors come out of a map, and an unsorted list
		// makes the same misconfiguration look like a different fault on
		// every run.
		for _, k := range sortedKeys(parsed.Errors) {
			parts = append(parts, k+": "+parsed.Errors[k])
		}
		if len(parts) > 0 {
			return fmt.Errorf("%s failed: %s (HTTP %d)",
				what, strings.Join(parts, "; "), resp.StatusCode)
		}
	}
	return fmt.Errorf("%s failed: HTTP %d: %s",
		what, resp.StatusCode, strings.TrimSpace(string(raw)))
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─── preflight ──────────────────────────────────────────────────────────────
//
// Everything below is read-only, and exists so `cti-jira --check` can answer
// "would a create succeed?" without creating anything. Finding out by filing a
// ticket means the first answer is a ticket somebody has to delete.

// Account is who the token belongs to.
type Account struct {
	AccountID   string `json:"accountId"`
	Email       string `json:"emailAddress"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
}

// Myself verifies the credentials and reports the account they carry.
//
// Worth printing: an API token has every permission its account has, so
// "which account is this" is the blast-radius question. A token quietly
// belonging to a departed admin looks identical to a service account here
// until you read the name.
func (c *Client) Myself(ctx context.Context) (Account, error) {
	var a Account
	if err := c.do(ctx, http.MethodGet, "/rest/api/2/myself", nil, &a); err != nil {
		return Account{}, err
	}
	return a, nil
}

// IssueTypeMeta is one creatable issue type in a project.
type IssueTypeMeta struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Subtask bool   `json:"subtask"`
}

// IssueTypes lists what may be created in a project.
//
// The paged createmeta endpoints, not the old monolithic
// /issue/createmeta?expand=... which Atlassian deprecated.
func (c *Client) IssueTypes(ctx context.Context, projectKey string) ([]IssueTypeMeta, error) {
	var out struct {
		IssueTypes []IssueTypeMeta `json:"issueTypes"`
	}
	path := "/rest/api/2/issue/createmeta/" + url.PathEscape(projectKey) + "/issuetypes"
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.IssueTypes, nil
}

// FieldMeta is one field on a create screen.
type FieldMeta struct {
	FieldID  string `json:"fieldId"`
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Schema   struct {
		Type   string `json:"type"`
		Custom string `json:"custom"`
	} `json:"schema"`
}

// CreateFields lists the create-screen fields for an issue type.
//
// This is what settles the open question about the CR project: the issue
// metadata reported 69 fields and none required, which is not credible for a
// screen that includes Summary. Either the report is filtered oddly or this
// project really does default everything - and the difference matters, because
// a Service Management desk commonly requires a request type that the plain
// issue API does not set.
func (c *Client) CreateFields(ctx context.Context, projectKey, issueTypeID string) ([]FieldMeta, error) {
	var out struct {
		Fields []FieldMeta `json:"fields"`
	}
	path := "/rest/api/2/issue/createmeta/" + url.PathEscape(projectKey) +
		"/issuetypes/" + url.PathEscape(issueTypeID)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Fields, nil
}

// ResolveIssueType maps a configured NAME to its id, and on failure says what
// the project actually offers.
//
// The error text is the point. "issuetype: Task is not valid for project CR"
// from a failed create tells you something is wrong; this tells you what to
// put in fleet.env instead.
func ResolveIssueType(types []IssueTypeMeta, name string) (IssueTypeMeta, error) {
	want := strings.TrimSpace(name)
	for _, t := range types {
		if strings.EqualFold(t.Name, want) {
			if t.Subtask {
				return IssueTypeMeta{}, fmt.Errorf(
					"issue type %q is a sub-task type and cannot be created on its own; "+
						"pick a top-level type", t.Name)
			}
			return t, nil
		}
	}
	var names []string
	for _, t := range types {
		if !t.Subtask {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	return IssueTypeMeta{}, fmt.Errorf(
		"JIRA_ISSUE_TYPE=%q does not exist in this project; it offers: %s",
		name, strings.Join(names, ", "))
}
