package graph

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testSince() time.Time {
	return time.Date(2026, 9, 2, 15, 8, 48, 0, time.UTC)
}

// The bug this guards against: an unescaped space in $orderby put a raw space
// in the HTTP request line, and the edge returned an HTML "Bad Request" page
// before Graph ever parsed the query.
func TestMessagesURLHasNoRawSpaces(t *testing.T) {
	u := messagesURL("cybersecurity@example.com", "inbox", testSince())
	if strings.ContainsAny(u, " \t\r\n") {
		t.Fatalf("URL contains raw whitespace, the edge will reject it:\n%s", u)
	}
}

func TestMessagesURLIsParseableAndRequestable(t *testing.T) {
	u := messagesURL("cybersecurity@example.com", "inbox", testSince())

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "graph.microsoft.com" {
		t.Errorf("unexpected scheme/host: %s://%s", parsed.Scheme, parsed.Host)
	}

	// net/http rejects a request line it cannot form, so this catches
	// characters that survive url.Parse but break on the wire.
	if _, err := http.NewRequest(http.MethodGet, u, nil); err != nil {
		t.Fatalf("http.NewRequest rejected the URL: %v", err)
	}
}

func TestMessagesURLQueryDecodesCorrectly(t *testing.T) {
	u := messagesURL("cybersecurity@example.com", "inbox", testSince())
	parsed, _ := url.Parse(u)
	q := parsed.Query()

	// Values must survive the round trip with their spaces intact.
	if got := q.Get("$orderby"); got != "receivedDateTime desc" {
		t.Errorf("$orderby = %q, want %q", got, "receivedDateTime desc")
	}
	if got := q.Get("$filter"); got != "receivedDateTime ge 2026-09-02T15:08:48Z" {
		t.Errorf("$filter = %q", got)
	}
	if got := q.Get("$select"); got != "id,subject,receivedDateTime,from,body" {
		t.Errorf("$select = %q", got)
	}
	if got := q.Get("$top"); got != "50" {
		t.Errorf("$top = %q, want 50", got)
	}
	// "$" must stay literal so these URLs match Graph's own documentation.
	if strings.Contains(u, "%24") {
		t.Error("OData $ prefixes were percent-encoded to %24")
	}
}

func TestMessagesURLFilterIsUTCAndRFC3339(t *testing.T) {
	// A non-UTC input must still produce a Z-suffixed instant: an unencoded
	// "+" in a timezone offset would be read as a space by the server.
	loc := time.FixedZone("EDT", -4*3600)
	u := messagesURL("m@example.com", "inbox", time.Date(2026, 9, 2, 11, 8, 48, 0, loc))
	parsed, _ := url.Parse(u)
	got := parsed.Query().Get("$filter")
	if !strings.HasSuffix(got, "Z") {
		t.Errorf("$filter is not a UTC instant: %q", got)
	}
	if got != "receivedDateTime ge 2026-09-02T15:08:48Z" {
		t.Errorf("$filter = %q, want the UTC equivalent", got)
	}
}

func TestMessagesURLEscapesMailboxAndFolder(t *testing.T) {
	// Shared mailboxes and folder names can contain characters that must not
	// break out of the path segment.
	u := messagesURL("cyber security+team@example.com", "CTI Feeds/2026", testSince())
	if strings.ContainsAny(u, " ") {
		t.Fatalf("unescaped space from mailbox or folder:\n%s", u)
	}
	if _, err := http.NewRequest(http.MethodGet, u, nil); err != nil {
		t.Fatalf("http.NewRequest rejected the URL: %v", err)
	}
}

func TestGraphErrorNamesHTMLResponses(t *testing.T) {
	html := []byte(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
<HTML><HEAD><TITLE>Bad Request</TITLE></HEAD>
<BODY><h2>Bad Request</h2><p>HTTP Error 400. The request is badly formed.</p></BODY></HTML>`)
	err := graphError(400, html, "https://graph.microsoft.com/v1.0/users/x/messages?$orderby=a b")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"before reaching the API", "malformed URL", "OData"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q:\n%s", want, msg)
		}
	}
}

func TestGraphErrorParsesJSONAndHints(t *testing.T) {
	cases := []struct {
		name, body, wantCode, wantHint string
	}{
		{
			name:     "access denied gets a permissions hint",
			body:     `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`,
			wantCode: "ErrorAccessDenied",
			wantHint: "APPLICATION permission",
		},
		{
			name:     "missing mailbox gets a config hint",
			body:     `{"error":{"code":"ResourceNotFound","message":"Mailbox not found."}}`,
			wantCode: "ResourceNotFound",
			wantHint: "GRAPH_MAILBOX",
		},
		{
			name:     "bad property gets an odata hint",
			body:     `{"error":{"code":"ErrorInvalidProperty","message":"Bad select."}}`,
			wantCode: "ErrorInvalidProperty",
			wantHint: "$select",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := graphError(403, []byte(tc.body), "https://graph.microsoft.com/x")
			msg := err.Error()
			if !strings.Contains(msg, tc.wantCode) {
				t.Errorf("missing code %q:\n%s", tc.wantCode, msg)
			}
			if !strings.Contains(msg, tc.wantHint) {
				t.Errorf("missing hint %q:\n%s", tc.wantHint, msg)
			}
		})
	}
}

func TestGraphErrorTruncatesUnrecognizedBodies(t *testing.T) {
	err := graphError(500, []byte(strings.Repeat("x", 5000)), "https://graph.microsoft.com/x")
	if len(err.Error()) > 1200 {
		t.Errorf("error message not truncated: %d chars", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "...") {
		t.Error("expected a truncation marker")
	}
}
