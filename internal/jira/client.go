package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
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
	BaseURL string // https://example.atlassian.net - the site; browse links use it
	// APIBase, when set, is where API calls go instead of BaseURL: the
	// Atlassian gateway, which a SCOPED API token requires (it is refused at
	// the site URL). Browse links stay on BaseURL, because the gateway serves
	// no web pages. See CloudGateway.
	APIBase string
	Email   string
	Token   string
	HTTP    *http.Client
}

// api is where API requests go.
func (c *Client) api() string {
	if c.APIBase != "" {
		return c.APIBase
	}
	return c.BaseURL
}

var cloudIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CloudGateway is the API base for a scoped token: the Atlassian gateway for
// this cloud id (JIRA_CLOUD_ID, from https://<site>/_edge/tenant_info). Only a
// UUID is accepted, so the value can never steer the credentials anywhere but
// api.atlassian.com.
func CloudGateway(cloudID string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(cloudID))
	if !cloudIDRE.MatchString(id) {
		return "", fmt.Errorf("JIRA_CLOUD_ID is not a cloud id (a UUID, from https://<site>/_edge/tenant_info)")
	}
	return "https://api.atlassian.com/ex/jira/" + id, nil
}

// New builds a client with a timeout that is bounded but generous: attachment
// uploads are slower than JSON calls and a ticket half-filed is worse than one
// that took a while.
func New(baseURL, email, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Email:   email,
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second, CheckRedirect: httpsOnly},
	}
}

// httpsOnly refuses a redirect to anything but https. Go drops Authorization
// on a redirect to another host, but not on a same-host downgrade to http,
// which would send the token in clear.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing a redirect to %s://%s: not https", req.URL.Scheme, req.URL.Host)
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
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
	// AssigneeAccountID assigns the new issue; "" leaves it unassigned.
	AssigneeAccountID string
	// Components are component NAMES; one that does not exist in the
	// project makes Jira refuse the whole create, so callers that pass one
	// retry without it.
	Components []string
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
	fields := map[string]any{
		"project":     map[string]string{"key": r.ProjectKey},
		"issuetype":   map[string]string{"name": r.IssueType},
		"summary":     r.Summary,
		"description": r.Description,
		"labels":      r.Labels,
	}
	body := map[string]any{"fields": fields}
	if r.AssigneeAccountID != "" {
		fields["assignee"] = map[string]string{"accountId": r.AssigneeAccountID}
	}
	if len(r.Components) > 0 {
		var cs []map[string]string
		for _, c := range r.Components {
			cs = append(cs, map[string]string{"name": c})
		}
		fields["components"] = cs
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

// AccountIDForEmail finds the Jira user with exactly this email address.
//
// Jira's user search matches on name and email fragments, so the result is
// accepted only when exactly one ACTIVE user's address equals the email
// (case-insensitively) - or, when the tenant hides addresses from the API,
// when the search returned exactly one active user and its address is hidden. Anything else is
// "not found": assigning an Urgent finding to the wrong person is worse than
// leaving it unassigned and saying so. Needs the "Browse users and groups"
// permission for the API account.
func (c *Client) AccountIDForEmail(ctx context.Context, email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", fmt.Errorf("no email to look up")
	}
	var users []struct {
		AccountID    string `json:"accountId"`
		EmailAddress string `json:"emailAddress"`
		Active       bool   `json:"active"`
		AccountType  string `json:"accountType"`
	}
	path := "/rest/api/3/user/search?query=" + url.QueryEscape(email) + "&maxResults=10"
	if err := c.do(ctx, http.MethodGet, path, nil, &users); err != nil {
		return "", err
	}
	var exact, active, hidden []string
	for _, u := range users {
		if !u.Active || u.AccountID == "" || (u.AccountType != "" && u.AccountType != "atlassian") {
			continue
		}
		active = append(active, u.AccountID)
		if strings.TrimSpace(u.EmailAddress) == "" {
			hidden = append(hidden, u.AccountID)
		}
		if strings.EqualFold(strings.TrimSpace(u.EmailAddress), email) {
			exact = append(exact, u.AccountID)
		}
	}
	switch {
	case len(exact) == 1:
		return exact[0], nil
	case len(exact) > 1:
		return "", fmt.Errorf("%d Jira users have the address %s", len(exact), email)
	case len(active) == 1 && len(hidden) == 1:
		// The one match's address is hidden by the tenant's privacy
		// settings, so it cannot be compared - but it is the only active
		// user the search found. A VISIBLE address that differs (a prefix
		// match, jsmith@ vs jsmith@...au) is never accepted.
		return hidden[0], nil
	}
	return "", fmt.Errorf("no single active Jira user found for %s (%d match(es))", email, len(active))
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

// AddWatcher adds a user to an issue's watchers. Adding someone already
// watching is harmless, so callers may repeat it every run. Needs the "Manage
// watcher list" permission (or the user adding themselves).
func (c *Client) AddWatcher(ctx context.Context, key, accountID string) error {
	// The API takes a bare JSON string: json.Marshal of a Go string is that.
	path := "/rest/api/2/issue/" + url.PathEscape(key) + "/watchers"
	return c.do(ctx, http.MethodPost, path, accountID, nil)
}

// RelatesLink is Jira's stock "relates to" link type.
const RelatesLink = "Relates"

// LinkIssues links two issues with a link type by NAME. Needs the "Link
// issues" project permission.
func (c *Client) LinkIssues(ctx context.Context, linkType, inwardKey, outwardKey string) error {
	body := map[string]any{
		"type":         map[string]string{"name": linkType},
		"inwardIssue":  map[string]string{"key": inwardKey},
		"outwardIssue": map[string]string{"key": outwardKey},
	}
	return c.do(ctx, http.MethodPost, "/rest/api/2/issueLink", body, nil)
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

	path := c.api() + "/rest/api/2/issue/" + url.PathEscape(key) + "/attachments"
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
	req, err := http.NewRequestWithContext(ctx, method, c.api()+path, body)
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
		return &StatusError{Code: resp.StatusCode, Err: fmt.Errorf("%s failed: THIS ENDPOINT HAS BEEN REMOVED by Atlassian "+
			"(HTTP 410) - this needs a code change, not a config change: %s",
			what, strings.TrimSpace(string(raw)))}
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
			return &StatusError{Code: resp.StatusCode, Err: fmt.Errorf("%s failed: %s (HTTP %d)",
				what, strings.Join(parts, "; "), resp.StatusCode)}
		}
	}
	return &StatusError{Code: resp.StatusCode, Err: fmt.Errorf("%s failed: HTTP %d: %s",
		what, resp.StatusCode, strings.TrimSpace(string(raw)))}
}

// StatusError is a non-2xx answer from Jira. A caller that must tell "Jira
// refused this request" (a 400: nothing was created) from "the request may
// or may not have landed" (a timeout, a 5xx) checks Code - retrying the
// second kind can file a duplicate.
type StatusError struct {
	Code int
	Err  error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

// IsBadRequest reports whether err is Jira refusing the request outright.
func IsBadRequest(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusBadRequest
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

// FleetPermissions are the Jira permissions the fleet uses: in the project
// (find, file, comment, attach, record state, assign, add watchers) and the
// global one for looking owners up by email.
var FleetPermissions = []string{"BROWSE_PROJECTS", "CREATE_ISSUES", "ADD_COMMENTS",
	"CREATE_ATTACHMENTS", "EDIT_ISSUES", "ASSIGN_ISSUES", "MANAGE_WATCHERS", "LINK_ISSUES", "USER_PICKER"}

// MyPermissions reports which of perms the token's account has in a project.
// Read-only: it answers "would the fleet's writes be allowed?" without
// writing anything.
func (c *Client) MyPermissions(ctx context.Context, projectKey string, perms []string) (map[string]bool, error) {
	var out struct {
		Permissions map[string]struct {
			HavePermission bool `json:"havePermission"`
		} `json:"permissions"`
	}
	path := "/rest/api/2/mypermissions?projectKey=" + url.QueryEscape(projectKey) +
		"&permissions=" + url.QueryEscape(strings.Join(perms, ","))
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, p := range perms {
		have[p] = out.Permissions[p].HavePermission
	}
	return have, nil
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

// ─── issue properties ───────────────────────────────────────────────────────

// GetProperty reads a JSON property off an issue into out.
//
// Returns found=false for a 404 rather than an error, because "this ticket has
// no state yet" is the normal case on the first run and on every ticket filed
// before state existed. Treating it as a failure would make the first update
// after deploying this look like a broken integration.
func (c *Client) GetProperty(ctx context.Context, issueKey, propKey string, out any) (bool, error) {
	path := c.api() + "/rest/api/2/issue/" + url.PathEscape(issueKey) +
		"/properties/" + url.PathEscape(propKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, fmt.Errorf("building the property request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("reading property %s on %s: %w", propKey, issueKey, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if err := checkStatus(resp, "read property "+propKey+" on "+issueKey); err != nil {
		return false, err
	}
	// The payload wraps the stored value: {"key":"...","value":{...}}.
	var wrapper struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return false, fmt.Errorf("decoding property %s on %s: %w", propKey, issueKey, err)
	}
	if len(wrapper.Value) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(wrapper.Value, out); err != nil {
		// A property this fleet wrote in an older format is not a reason to
		// fail the run. Report it as absent and let the caller rewrite it:
		// the cost is one missed drift comparison, not a dead lane.
		return false, fmt.Errorf("property %s on %s is not in the expected format "+
			"(it will be rewritten): %w", propKey, issueKey, err)
	}
	return true, nil
}

// SetProperty writes a JSON property onto an issue.
//
// PUT replaces outright, which is what is wanted: the state is the whole
// picture of what the fleet last believed, not an accumulation.
func (c *Client) SetProperty(ctx context.Context, issueKey, propKey string, value any) error {
	path := "/rest/api/2/issue/" + url.PathEscape(issueKey) +
		"/properties/" + url.PathEscape(propKey)
	return c.do(ctx, http.MethodPut, path, value, nil)
}
