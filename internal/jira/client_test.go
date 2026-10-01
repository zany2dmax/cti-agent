package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every test here runs against httptest, never against a tenant. A client
// whose only test is "it worked against the real Jira once" cannot be run in
// CI, and is therefore not run.

func TestCreateIssueSendsTheShapeJiraExpects(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var body map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotCT = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"10001","key":"CR-1234","self":"http://x/rest/api/2/issue/10001"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "svc@crhomeusa.com", "tok")
	got, err := c.CreateIssue(context.Background(), IssueRequest{
		ProjectKey:  "CR",
		IssueType:   "IT Support",
		Summary:     "CVE-2026-85880 - 441 hosts",
		Description: "body",
		Labels:      []string{"cti-cve-2026-85880"},
	})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if got.Key != "CR-1234" {
		t.Errorf("key = %q, want CR-1234", got.Key)
	}

	// v2, not v3. v3 would require the description as an ADF document tree
	// and this plain string would be rejected.
	if gotPath != "/rest/api/2/issue" {
		t.Errorf("path = %q, want /rest/api/2/issue", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc@crhomeusa.com:tok"))
	if gotAuth != wantAuth {
		t.Error("Authorization header is not email:token basic auth")
	}

	fields, ok := body["fields"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no fields object: %v", body)
	}
	if p, _ := fields["project"].(map[string]any); p["key"] != "CR" {
		t.Errorf("project = %v, want key CR", fields["project"])
	}
	// issuetype by NAME, because the name is what fleet.env carries. The CR
	// project has no "Task" type at all, so this is the field that fails
	// loudest when it is misconfigured.
	if it, _ := fields["issuetype"].(map[string]any); it["name"] != "IT Support" {
		t.Errorf("issuetype = %v, want name 'IT Support'", fields["issuetype"])
	}
	if fields["description"] != "body" {
		t.Errorf("description was not sent as a plain string: %v", fields["description"])
	}
}

func TestCreateIssueReportsJirasFieldErrors(t *testing.T) {
	// The diagnosis IS the per-field errors map. "jira returned 400" sends
	// somebody reading HTTP docs; "issuetype: Task is not valid" sends them
	// to fleet.env. This is the exact error the CR project would return for
	// the obvious default.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorMessages":[],"errors":{
			"issuetype":"Task is not valid for project CR",
			"customfield_10010":"Request type is required"}}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "a@b.c", "t").CreateIssue(context.Background(),
		IssueRequest{ProjectKey: "CR", IssueType: "Task", Summary: "x"})
	if err == nil {
		t.Fatal("a 400 was reported as success")
	}
	msg := err.Error()
	for _, want := range []string{"issuetype", "Task is not valid", "customfield_10010", "400"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error omits %q: %v", want, msg)
		}
	}
	// Sorted: the field errors come from a map, and an unstable order makes
	// one misconfiguration look like several different faults across runs.
	if strings.Index(msg, "customfield_10010") > strings.Index(msg, "issuetype") {
		t.Errorf("field errors are not sorted: %v", msg)
	}
}

func TestCreateIssueRejectsA2xxWithNoKey(t *testing.T) {
	// A proxy or a misrouted call can return 200 and something that is not an
	// issue. Treating that as success means the ticket is reported as filed
	// and does not exist.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "a@b.c", "t").CreateIssue(context.Background(),
		IssueRequest{ProjectKey: "CR", IssueType: "IT Support", Summary: "x"}); err == nil {
		t.Fatal("a 200 with no issue key was accepted")
	}
}

func TestAttachSendsTheXSRFOptOutAndTheFieldNamedFile(t *testing.T) {
	// Both are Jira requirements and both are easy to miss. Without the
	// token header the upload 403s while every other call on the same
	// credentials succeeds, which reads like a permissions problem.
	var gotToken, gotField, gotFilename string
	var gotContent []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Atlassian-Token")
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Errorf("content-type: %v", err)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			t.Errorf("reading the multipart body: %v", err)
			return
		}
		gotField, gotFilename = part.FormName(), part.FileName()
		gotContent, _ = io.ReadAll(part)
		_, _ = w.Write([]byte(`[{"id":"1"}]`))
	}))
	defer srv.Close()

	csvBody := []byte("hostname,cve,qids\nhost-a0,CVE-2026-85880,92101 92145\n")
	if err := New(srv.URL, "a@b.c", "t").Attach(
		context.Background(), "CR-1234", "cve-2026-85880-hosts-2026-10-01.csv", csvBody); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	if gotToken != "no-check" {
		t.Errorf("X-Atlassian-Token = %q, want no-check", gotToken)
	}
	if gotField != "file" {
		t.Errorf("form field = %q, want exactly \"file\"", gotField)
	}
	if gotFilename != "cve-2026-85880-hosts-2026-10-01.csv" {
		t.Errorf("filename = %q", gotFilename)
	}
	if string(gotContent) != string(csvBody) {
		t.Error("attachment content was altered in transit")
	}
}

func TestSearchUsesTheEndpointThatStillExists(t *testing.T) {
	// /rest/api/2/search answers HTTP 410 - removed, not deprecated. This
	// test exists because the original code was correct when written and
	// broke without any change to it, and nothing in a stub would have caught
	// that. Pinning the path means a future "tidy up to one API version"
	// cannot silently put it back.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"issues":[],"isLast":true}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "a@b.c", "t").Search(context.Background(), "project = CR", 5); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if gotPath != "/rest/api/3/search/jql" {
		t.Errorf("path = %q, want /rest/api/3/search/jql", gotPath)
	}
}

func TestARemovedEndpointSaysSoInWords(t *testing.T) {
	// An EOL reads like a transient failure until something says the word.
	// Qualys retired the 2.0 KnowledgeBase the same way, and the cost there
	// was time spent looking for a credential problem.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"errorMessages":["The requested API has been removed. ` +
			`Please migrate to the /rest/api/3/search/jql API."]}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "a@b.c", "t").Search(context.Background(), "project = CR", 5)
	if err == nil {
		t.Fatal("a 410 was reported as success")
	}
	msg := err.Error()
	if !strings.Contains(msg, "REMOVED") {
		t.Errorf("a 410 does not name itself as a removal: %v", msg)
	}
	if !strings.Contains(msg, "code change, not a config change") {
		t.Errorf("a 410 does not say who can fix it: %v", msg)
	}
	// The replacement path is in Atlassian's body. Losing it means the next
	// person has to go and find the changelog entry.
	if !strings.Contains(msg, "/rest/api/3/search/jql") {
		t.Errorf("the replacement path was dropped from the error: %v", msg)
	}
}

func TestSearchAsksForTheMinimumAndParsesStatusCategory(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"issues":[{"key":"CR-1234","fields":{
			"summary":"CVE-2026-85880 - 441 hosts",
			"status":{"name":"Hand Rolled Closed State",
			          "statusCategory":{"key":"done","name":"Done"}},
			"labels":["cti-cve-2026-85880"]}}]}`))
	}))
	defer srv.Close()

	got, err := New(srv.URL, "a@b.c", "t").Search(
		context.Background(), FindJQL("CR", "CVE-2026-85880"), 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].Key != "CR-1234" {
		t.Fatalf("got %+v", got)
	}
	// Read from the CATEGORY, not the name. Status names are per-project and
	// renamed freely, so matching on "Done" or "Closed" ties the fleet's idea
	// of finished to a workflow anybody can edit.
	if !got[0].IsDone() {
		t.Error("a done-category status was not recognised as done")
	}
	if body["jql"] == "" {
		t.Error("no JQL was sent")
	}
	// Not hygiene any more. /rest/api/3/search/jql returns ONLY the issue id
	// unless fields are named, so an unasked-for status field comes back
	// empty - IsDone would then report every ticket as not-done while the
	// duplicate check carried on working, which is the quiet kind of wrong.
	f, _ := body["fields"].([]any)
	if len(f) == 0 {
		t.Fatal("search named no fields - the new endpoint returns only the id")
	}
	want := map[string]bool{"status": false, "labels": false, "summary": false}
	for _, v := range f {
		if name, ok := v.(string); ok {
			if _, tracked := want[name]; tracked {
				want[name] = true
			}
		}
	}
	for name, asked := range want {
		if !asked {
			t.Errorf("search did not ask for %q, so it will come back empty", name)
		}
	}
}

func TestAnHTMLErrorPageIsBoundedNotDumped(t *testing.T) {
	// A proxy intercepting the call returns HTML. The whole page in the
	// journal is not a diagnosis, and this fleet logs to a journal people
	// read.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>" + strings.Repeat("x", 50_000) + "</html>"))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "a@b.c", "t").CreateIssue(context.Background(),
		IssueRequest{ProjectKey: "CR", IssueType: "IT Support", Summary: "x"})
	if err == nil {
		t.Fatal("a 502 was reported as success")
	}
	if len(err.Error()) > maxErrorBody+500 {
		t.Errorf("error is %d bytes - an error page was dumped whole", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error does not name the status: %v", err)
	}
}

func TestBrowseURLIsForHumansNotTheAPI(t *testing.T) {
	// The API's "self" field points at the REST endpoint, which is useless in
	// an email. The digest needs a link somebody can click.
	c := New("https://crhomeusa.atlassian.net/", "a@b.c", "t")
	if got := c.BrowseURL("CR-1234"); got != "https://crhomeusa.atlassian.net/browse/CR-1234" {
		t.Errorf("BrowseURL = %q", got)
	}
}
