package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bigList(lines int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "* TXT {{host%04d.example.com}}: add {{v=spf1 -all}} - nothing sends mail as it\n", i)
	}
	return b.String()
}

func TestShortTextIsNotSplit(t *testing.T) {
	if got := SplitText("small", MaxText); len(got) != 1 || got[0] != "small" {
		t.Fatalf("got %q", got)
	}
}

// The real failure: a list of 206 changes was refused whole by Jira.
func TestALongListSplitsAtLinesUnderTheLimit(t *testing.T) {
	text := bigList(900) // well over 32767 characters
	if len([]rune(text)) <= 32767 {
		t.Fatalf("test text too short: %d", len([]rune(text)))
	}
	parts := SplitText(text, MaxText)
	if len(parts) < 2 {
		t.Fatalf("not split")
	}
	var lines int
	for i, p := range parts {
		if n := len([]rune(p)); n > 32767 {
			t.Errorf("part %d is %d characters", i+1, n)
		}
		for _, l := range strings.Split(p, "\n") {
			if strings.HasPrefix(l, "* TXT") {
				lines++
				if !strings.HasSuffix(l, "mail as it") {
					t.Errorf("part %d tears a line: %q", i+1, l)
				}
			}
		}
	}
	if lines != 900 {
		t.Errorf("%d list lines survive the split, want 900", lines)
	}
	if !strings.Contains(parts[0], "continues in the next comment") ||
		!strings.Contains(parts[1], "part 2 of") {
		t.Error("parts do not say they are parts")
	}
}

func TestOneEnormousLineIsStillCut(t *testing.T) {
	parts := SplitText(strings.Repeat("é", 70000), MaxText)
	for i, p := range parts {
		if n := len([]rune(p)); n > 32767 {
			t.Errorf("part %d is %d characters", i+1, n)
		}
	}
	if len(parts) < 3 {
		t.Errorf("got %d parts", len(parts))
	}
}

func jiraThatRefusesLongText(t *testing.T, posted *[]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		text, _ := body["body"].(string)
		if f, ok := body["fields"].(map[string]any); ok {
			text, _ = f["description"].(string)
		}
		if len([]rune(text)) > 32767 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":{"comment":"The entered text is too long."}}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/comment") {
			*posted = append(*posted, text)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"1","key":"INF-1","self":"x"}`))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "svc@example.com", "tok")
}

func TestAddCommentPostsALongListInParts(t *testing.T) {
	var posted []string
	c := jiraThatRefusesLongText(t, &posted)
	if err := c.AddComment(context.Background(), "INF-590", bigList(900)); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if len(posted) < 2 {
		t.Fatalf("posted %d comment(s), want several", len(posted))
	}
	if n := strings.Count(strings.Join(posted, "\n"), "* TXT"); n != 900 {
		t.Errorf("%d list lines arrived, want 900", n)
	}
}

func TestCreateIssueWithALongDescriptionCommentsTheRest(t *testing.T) {
	var posted []string
	c := jiraThatRefusesLongText(t, &posted)
	res, err := c.CreateIssue(context.Background(), IssueRequest{
		ProjectKey: "INF", IssueType: "Task", Summary: "s", Description: bigList(900)})
	if err != nil || res.Key != "INF-1" {
		t.Fatalf("CreateIssue: %v %+v", err, res)
	}
	if len(posted) == 0 {
		t.Error("the overflow was not posted as comments")
	}
}
