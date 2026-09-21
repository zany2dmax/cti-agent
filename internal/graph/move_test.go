package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// IsAutoReply decides whether a message is eligible to be moved to Deleted
// Items, so it is the highest-consequence pure function in this package. It
// had no test.

func TestIsAutoReplyTrustsOnlyTheSendersDeclaration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		msg       Message
		want      bool
		reasoning string
	}{
		{"RFC 3834 auto-replied", Message{AutoSubmitted: "auto-replied"}, true,
			"the value RFC 3834 reserves for vacation notices"},
		{"case and whitespace", Message{AutoSubmitted: "  Auto-Replied  "}, true,
			"headers arrive however the sender felt like writing them"},
		{"auto-notified", Message{AutoSubmitted: "auto-notified"}, true,
			"also a machine reply to a human's message"},

		// The important negative. RFC 3834 distinguishes auto-GENERATED - a
		// report or notification a system produced on its own - from
		// auto-REPLIED. A vendor advisory from a mailing system is
		// auto-generated, and deleting those would delete the input this
		// entire fleet exists to read.
		{"auto-generated is NOT an auto-reply", Message{AutoSubmitted: "auto-generated"}, false,
			"a vendor advisory from a mailing system sets this"},

		{"no header at all", Message{}, false,
			"absence of a declaration is not a declaration"},
		{"suppress alone is not enough", Message{AutoResponseSuppress: "All"}, false,
			"plenty of automated mail sets this to stop reply storms"},
		{"suppress plus an auto declaration", Message{
			AutoSubmitted: "auto-replied", AutoResponseSuppress: "All"}, true,
			"the Exchange out-of-office shape"},

		// Subject text must never matter here. It is trivially forgeable and
		// easy to hit by accident, and this function gates a deletion.
		{"subject looks like an OOO", Message{
			Subject: "Automatic reply: Out of Office"}, false,
			"subject text does not delete mail"},
		{"subject mentions CVE and OOO", Message{
			Subject: "Out of Office: CVE-2026-1 advisory"}, false,
			"still no header, still not an auto-reply"},
	} {
		if got := tc.msg.IsAutoReply(); got != tc.want {
			t.Errorf("%s: IsAutoReply() = %v, want %v - %s",
				tc.name, got, tc.want, tc.reasoning)
		}
	}
}

// ---------------------------------------------------------------- MoveMessage

func TestMoveMessageRefusesBeforeTouchingTheNetwork(t *testing.T) {
	// A client with no endpoints: if any of these reaches the wire the test
	// fails with a connection error rather than passing quietly.
	c := New("t", "c", "s")
	c.tokenEndpoint = "http://127.0.0.1:1/token"
	c.graphBase = "http://127.0.0.1:1"

	for _, tc := range []struct {
		name, mailbox, id string
		dest              Folder
		wantErr           string
	}{
		{"unknown folder", "m@example.com", "AAA", Folder("junkemail"), "unknown destination"},
		{"empty folder", "m@example.com", "AAA", Folder(""), "unknown destination"},
		// The one that matters: nothing in this package can express a purge,
		// so a caller trying to invent one is refused rather than accepted
		// and silently misrouted.
		{"attempted purge", "m@example.com", "AAA", Folder("recoverableitemspurges"), "unknown destination"},
		{"no mailbox", "", "AAA", FolderArchive, "both required"},
		{"no message id", "m@example.com", "", FolderArchive, "both required"},
	} {
		_, err := c.MoveMessage(context.Background(), tc.mailbox, tc.id, tc.dest)
		if err == nil {
			t.Errorf("%s: expected a refusal, got nil", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q should mention %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestMoveMessagePostsToTheRightPlace(t *testing.T) {
	var gotPath, gotBody, gotAuth, gotMethod string
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"NEW-ID-AFTER-MOVE"}`))
	})
	defer srv.Close()

	newID, err := c.MoveMessage(context.Background(),
		"cybersecurity@example.com", "AAMkAD/x+y=", FolderDeletedItems)
	if err != nil {
		t.Fatalf("MoveMessage: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	// The message ID is base64-ish and contains / and + and =, which must be
	// escaped or the path silently addresses a different resource.
	if !strings.Contains(gotPath, "/users/cybersecurity@example.com/messages/") {
		t.Errorf("path = %q", gotPath)
	}
	if strings.Contains(gotPath, "AAMkAD/x+y=") {
		t.Errorf("the message ID was not escaped into the path: %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body is not JSON: %q", gotBody)
	}
	if payload["destinationId"] != "deleteditems" {
		t.Errorf("destinationId = %q, want deleteditems", payload["destinationId"])
	}

	// The ID changes on a move, and the caller records what it did - a record
	// pointing at an ID that no longer resolves cannot be checked afterwards.
	if newID != "NEW-ID-AFTER-MOVE" {
		t.Errorf("newID = %q, want the post-move ID", newID)
	}
}

func TestMoveMessageArchiveUsesTheArchiveFolder(t *testing.T) {
	var body string
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	})
	defer srv.Close()
	if _, err := c.MoveMessage(context.Background(), "m@example.com", "AAA", FolderArchive); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"destinationId":"archive"`) {
		t.Errorf("body = %q", body)
	}
}

func TestMoveMessage403NamesTheMissingPermission(t *testing.T) {
	// This is the error he will actually see, because Mail.ReadWrite needs a
	// fresh admin consent. "403 Forbidden" alone sends people to the wrong
	// place - the access policy, the mailbox licence, the secret.
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`))
	})
	defer srv.Close()

	_, err := c.MoveMessage(context.Background(), "m@example.com", "AAA", FolderArchive)
	if err == nil {
		t.Fatal("expected an error on 403")
	}
	for _, want := range []string{"Mail.ReadWrite", "APPLICATION", "admin consent",
		"Mail.Read is not enough", "Application Access Policy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("403 error should mention %q:\n  %v", want, err)
		}
	}
}

func TestMoveMessage404SaysItMayAlreadyBeMoved(t *testing.T) {
	// Two runs in a day, or a person tidying by hand, and the message is gone
	// from the inbox. That is not a fault and the message should not read like
	// one.
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"ErrorItemNotFound"}}`))
	})
	defer srv.Close()

	_, err := c.MoveMessage(context.Background(), "m@example.com", "AAA", FolderArchive)
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("404 should suggest it was already moved, got %v", err)
	}
}

func TestMoveMessageSucceedsEvenWhenTheBodyIsUnreadable(t *testing.T) {
	// A 2xx means the move happened. Failing on an unparseable body would
	// report a failure for something that succeeded, and the caller would
	// retry a move that has already been done.
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})
	defer srv.Close()

	newID, err := c.MoveMessage(context.Background(), "m@example.com", "AAA", FolderArchive)
	if err != nil {
		t.Errorf("a 2xx with a junk body is still a completed move: %v", err)
	}
	if newID != "" {
		t.Errorf("newID = %q, want empty when it could not be parsed", newID)
	}
}
