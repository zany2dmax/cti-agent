package jira

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/audit"
)

// auditTo sends this test's audit events to a temp directory and returns it.
func auditTo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	restore := audit.SetDefault(&audit.Logger{Dir: dir, Lane: "cti-jira", Actor: "tester", Run: "run-1", Host: "host-a", Pid: 1})
	t.Cleanup(restore)
	return dir
}

func auditLines(t *testing.T, dir string) []string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	var out []string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

func jiraServer(t *testing.T, status int, body string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEveryJiraWriteIsAudited(t *testing.T) {
	dir := auditTo(t)
	srv := jiraServer(t, http.StatusCreated, `{"id":"1","key":"CR-7","self":"x"}`)
	c := New(srv.URL, "svc@example.com", "tok")
	ctx := context.Background()

	if _, err := c.CreateIssue(ctx, IssueRequest{ProjectKey: "CR", IssueType: "Task", Summary: "SECRET-SUMMARY", Description: "SECRET-BODY"}); err != nil {
		t.Fatal(err)
	}
	_ = c.AddComment(ctx, "CR-7", "SECRET-COMMENT")
	_ = c.AddWatcher(ctx, "CR-7", "acct-1")
	_ = c.LinkIssues(ctx, RelatesLink, "CR-7", "CR-8")
	_ = c.Attach(ctx, "CR-7", "SECRET-FILENAME.txt", []byte("SECRET-CONTENT"))

	lines := auditLines(t, dir)
	want := []struct{ action, target string }{
		{"jira.issue.create", `target="CR-7"`},
		{"jira.comment.add", `target="CR-7"`},
		{"jira.watcher.add", `target="CR-7"`},
		{"jira.issue.link", `target="CR-7 -> CR-8"`},
		{"jira.attachment.add", `target="CR-7"`},
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d events, want %d:\n%s", len(lines), len(want), strings.Join(lines, "\n"))
	}
	for i, w := range want {
		if !strings.Contains(lines[i], " "+w.action+" ") || !strings.Contains(lines[i], w.target) || !strings.Contains(lines[i], `outcome="success"`) {
			t.Errorf("event %d: want %s %s success, got %s", i, w.action, w.target, lines[i])
		}
	}
	// Nothing the ticket says goes in the trail.
	if joined := strings.Join(lines, "\n"); strings.Contains(joined, "SECRET") {
		t.Errorf("ticket text reached the audit trail:\n%s", joined)
	}
}

func TestAFailedJiraWriteIsAuditedAsAFailureWithoutTheServersWords(t *testing.T) {
	dir := auditTo(t)
	srv := jiraServer(t, http.StatusForbidden, `{"errorMessages":["SERVER-TEXT-WITH-PRIVATE-DETAIL"]}`)
	c := New(srv.URL, "svc@example.com", "tok")
	if _, err := c.CreateIssue(context.Background(), IssueRequest{ProjectKey: "CR", IssueType: "Task", Summary: "s"}); err == nil {
		t.Fatal("want an error")
	}
	lines := auditLines(t, dir)
	if len(lines) != 1 {
		t.Fatalf("events: %v", lines)
	}
	l := lines[0]
	if !strings.HasPrefix(l, "<84>") || !strings.Contains(l, `outcome="failure"`) || !strings.Contains(l, `target="CR"`) {
		t.Errorf("a failure should be severity warning, outcome failure, target the project: %s", l)
	}
	if strings.Contains(l, "SERVER-TEXT") {
		t.Errorf("the server's error text reached the trail: %s", l)
	}
}

func TestJiraReadsAreNotAudited(t *testing.T) {
	dir := auditTo(t)
	srv := jiraServer(t, http.StatusOK, `{"transitions":[]}`)
	c := New(srv.URL, "svc@example.com", "tok")
	_, _ = c.Transitions(context.Background(), "CR-7")
	if lines := auditLines(t, dir); len(lines) != 0 {
		t.Fatalf("a read was audited: %v", lines)
	}
}

func TestTransitionsAreAudited(t *testing.T) {
	dir := auditTo(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"transitions":[{"id":"31","name":"Done","to":{"name":"Done"}}]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(srv.URL, "svc@example.com", "tok")
	if err := c.MoveTo(context.Background(), "CR-7", "Done"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background(), "CR-7", CloseChoice{Transition: Transition{ID: "31", Name: "Done"}}, "closing"); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, dir)
	if len(lines) != 2 || !strings.Contains(lines[0], " jira.issue.transition ") || !strings.Contains(lines[1], " jira.issue.close ") {
		t.Fatalf("events: %v", lines)
	}
}

func TestIssuePropertyWritesAreAudited(t *testing.T) {
	dir := auditTo(t)
	srv := jiraServer(t, http.StatusOK, `{}`)
	c := New(srv.URL, "svc@example.com", "tok")
	if err := c.SetProperty(context.Background(), "CR-7", "cti-appscan-state", map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	lines := auditLines(t, dir)
	if len(lines) != 1 || !strings.Contains(lines[0], " jira.property.set ") || !strings.Contains(lines[0], `target="CR-7"`) ||
		!strings.Contains(lines[0], "property=cti-appscan-state") {
		t.Fatalf("events: %v", lines)
	}
}

// A ticket that was created is a SUCCESS in the trail even when the comments
// carrying the rest of a long description failed: a query for created tickets
// must find it. The failed comments are their own event.
func TestACreatedTicketWithFailedContinuationCommentsIsStillASuccess(t *testing.T) {
	dir := auditTo(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/comment") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"1","key":"CR-9","self":"x"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "svc@example.com", "tok")
	long := strings.Repeat("word ", MaxText) // well over one description
	_, err := c.CreateIssue(context.Background(), IssueRequest{ProjectKey: "CR", IssueType: "Task", Summary: "s", Description: long})
	if err == nil {
		t.Fatal("want the continuation error back")
	}
	lines := auditLines(t, dir)
	if len(lines) != 2 {
		t.Fatalf("want a create and a comment event, got:\n%s", strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[0], " jira.issue.create ") || !strings.Contains(lines[0], `outcome="success"`) || !strings.Contains(lines[0], `target="CR-9"`) {
		t.Errorf("the created ticket should be a success: %s", lines[0])
	}
	if !strings.Contains(lines[1], " jira.comment.add ") || !strings.Contains(lines[1], `outcome="failure"`) {
		t.Errorf("the failed continuation should be its own failure: %s", lines[1])
	}
}
