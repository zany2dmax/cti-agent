package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// staleStub serves the token endpoint and hands every other request to h.
func staleStub(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New("tenant", "id", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL
	return c
}

func TestOldMessagesAsksForMailBeforeTheCutoffOldestFirstAndStopsAtTheCap(t *testing.T) {
	var queries []string
	var c *Client
	c = staleStub(t, func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		page := map[string]any{"value": []map[string]any{
			{"id": "a", "subject": "old", "receivedDateTime": "2026-09-01T10:00:00Z",
				"flag": map[string]string{"flagStatus": "notFlagged"}},
			{"id": "b", "subject": "flagged", "receivedDateTime": "2026-09-02T10:00:00Z",
				"flag": map[string]string{"flagStatus": "flagged"}},
			{"id": "c", "subject": "done", "receivedDateTime": "2026-09-03T10:00:00Z",
				"flag": map[string]string{"flagStatus": "complete"}},
		}, "@odata.nextLink": c.graphBase + "/next"}
		_ = json.NewEncoder(w).Encode(page)
	})
	cut := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	got, err := c.OldMessages(context.Background(), "cti@example.com", "inbox", cut, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d messages, want the cap of 4 across two pages", len(got))
	}
	if len(queries) != 2 {
		t.Errorf("%d requests, want 2 - it must stop paging once the cap is reached", len(queries))
	}
	q := queries[0]
	for _, want := range []string{"receivedDateTime+lt+2026-10-13T00%3A00%3A00Z", "receivedDateTime+asc", "flag", "$top=4"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q lacks %q", q, want)
		}
	}
	if strings.Contains(q, "body") || strings.Contains(q, "internetMessageHeaders") {
		t.Errorf("query %q reads bodies or headers - the sweep moves by age alone", q)
	}
	if got[0].Flagged || !got[1].Flagged || !got[2].Flagged {
		t.Errorf("flags = %v %v %v: notFlagged is the only unflagged state", got[0].Flagged, got[1].Flagged, got[2].Flagged)
	}
}

func TestFindChildFolderMatchesByNameAndQuotesIt(t *testing.T) {
	var gotFilter, gotPath string
	c := staleStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotFilter = r.URL.Path, r.URL.Query().Get("$filter")
		_, _ = w.Write([]byte(`{"value":[{"id":"F1","displayName":"Unhandled"}]}`))
	})
	f, ok, err := c.FindChildFolder(context.Background(), "cti@example.com", "inbox", "Unhandled")
	if err != nil || !ok || f.id != "F1" || f.Name != "Unhandled" {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
	if !strings.HasSuffix(gotPath, "/mailFolders/inbox/childFolders") || gotFilter != "displayName eq 'Unhandled'" {
		t.Errorf("path %q filter %q", gotPath, gotFilter)
	}

	_, _, _ = c.FindChildFolder(context.Background(), "cti@example.com", "inbox", "Bob's")
	if gotFilter != "displayName eq 'Bob''s'" {
		t.Errorf("filter %q: a single quote must be doubled, not end the string", gotFilter)
	}
}

func TestFindChildFolderSaysWhenThereIsNone(t *testing.T) {
	c := staleStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	if _, ok, err := c.FindChildFolder(context.Background(), "m@example.com", "inbox", "Unhandled"); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestCreateAndMoveUseTheFolderIdGraphReturned(t *testing.T) {
	var moveBody map[string]string
	c := staleStub(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/childFolders") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"NEW","displayName":"Unhandled"}`))
		case strings.HasSuffix(r.URL.Path, "/move"):
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &moveBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"MOVED"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	f, err := c.CreateChildFolder(context.Background(), "m@example.com", "inbox", "Unhandled")
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.MoveToChildFolder(context.Background(), "m@example.com", "MSG", f)
	if err != nil || id != "MOVED" || moveBody["destinationId"] != "NEW" {
		t.Fatalf("id %q err %v body %v", id, err, moveBody)
	}
}

func TestMoveToChildFolderNeedsAFolderThisPackageFound(t *testing.T) {
	c := New("t", "i", "s")
	if _, err := c.MoveToChildFolder(context.Background(), "m@example.com", "MSG", ChildFolder{Name: "Unhandled"}); err == nil {
		t.Fatal("a folder with no looked-up id must be refused before any request")
	}
}

func TestValidFolderName(t *testing.T) {
	for _, bad := range []string{"", " Unhandled", "Inbox/Unhandled", `a\b`, "a\nb", strings.Repeat("x", 65)} {
		if ValidFolderName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"Unhandled", "Fleet - Unhandled", "Bob's"} {
		if err := ValidFolderName(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
}
