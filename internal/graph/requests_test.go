package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func requestsStub(t *testing.T, handler func(path, query string) (int, string)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		status, body := handler(r.URL.Path, r.URL.RawQuery)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := New("tenant", "id", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL
	return c
}

const listing = `{"value":[
 {"id":"m1","conversationId":"c1","subject":"to the list","receivedDateTime":"2026-11-05T10:00:00Z","hasAttachments":true,
  "from":{"emailAddress":{"name":"A Sender","address":"a@example.test"}},
  "toRecipients":[{"emailAddress":{"address":"Supplier-Request@Example.test"}}],"ccRecipients":[],"body":{"content":"hello"}},
 {"id":"m2","conversationId":"c2","subject":"cc the list","receivedDateTime":"2026-11-05T09:00:00Z","hasAttachments":false,
  "from":{"emailAddress":{"address":"b@example.test"}},
  "toRecipients":[{"emailAddress":{"address":"someone@example.test"}}],
  "ccRecipients":[{"emailAddress":{"address":"supplier-request@example.test"}}],"body":{"content":"fyi"}},
 {"id":"m3","conversationId":"c3","subject":"not for the list","receivedDateTime":"2026-11-05T08:00:00Z","hasAttachments":false,
  "from":{"emailAddress":{"address":"c@example.test"}},
  "toRecipients":[{"emailAddress":{"address":"someone@example.test"}}],"ccRecipients":[],"body":{"content":"no"}}
]}`

func TestMessagesToOrCcTheAddressAreReturnedIgnoringCase(t *testing.T) {
	var gotPath string
	c := requestsStub(t, func(path, _ string) (int, string) { gotPath = path; return 200, listing })
	msgs, err := c.MessagesAddressedTo(context.Background(), "box@example.test", "inbox", "supplier-request@example.test", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].ID != "m1" || msgs[1].ID != "m2" {
		t.Fatalf("got %+v", msgs)
	}
	if msgs[0].From != "a@example.test" || msgs[0].FromName != "A Sender" || msgs[0].ConversationID != "c1" ||
		msgs[0].BodyText != "hello" || !msgs[0].HasAttachments || len(msgs[1].Cc) != 1 {
		t.Errorf("fields = %+v", msgs[0])
	}
	if !strings.Contains(gotPath, "/users/box@example.test/mailFolders/inbox/messages") {
		t.Errorf("path = %q", gotPath)
	}
}

func TestAnUnsetAddressIsAnErrorNotEveryMessage(t *testing.T) {
	c := requestsStub(t, func(string, string) (int, string) { return 200, listing })
	if _, err := c.MessagesAddressedTo(context.Background(), "box@example.test", "inbox", "  ", time.Now()); err == nil {
		t.Error("an empty address returned messages")
	}
}

func TestAttachmentsAreListedWithoutContent(t *testing.T) {
	var gotQuery string
	c := requestsStub(t, func(path, query string) (int, string) {
		gotQuery = query
		return 200, `{"value":[
		 {"@odata.type":"#microsoft.graph.fileAttachment","id":"a1","name":"form.xlsx","contentType":"x","size":47000,"isInline":false},
		 {"@odata.type":"#microsoft.graph.itemAttachment","id":"a2","name":"fwd","size":10,"isInline":false}]}`
	})
	atts, err := c.Attachments(context.Background(), "box@example.test", "m1")
	if err != nil || len(atts) != 2 {
		t.Fatalf("%v %v", atts, err)
	}
	if !atts[0].IsFile || atts[1].IsFile || atts[0].Size != 47000 {
		t.Errorf("atts = %+v", atts)
	}
	if strings.Contains(gotQuery, "contentBytes") {
		t.Errorf("listing asked for content: %q", gotQuery)
	}
}

func TestOneAttachmentIsDownloadedByIdAndBounded(t *testing.T) {
	var gotPath string
	c := requestsStub(t, func(path, _ string) (int, string) { gotPath = path; return 200, "file bytes" })
	b, err := c.AttachmentContent(context.Background(), "box@example.test", "m1", "a1", 1<<20)
	if err != nil || string(b) != "file bytes" {
		t.Fatalf("%q %v", b, err)
	}
	if !strings.HasSuffix(gotPath, "/messages/m1/attachments/a1/$value") {
		t.Errorf("path = %q", gotPath)
	}
	if _, err := c.AttachmentContent(context.Background(), "box@example.test", "m1", "a1", 4); err == nil {
		t.Error("a file over the limit was returned")
	}
}
