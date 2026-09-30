package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tokenAndSend stands up a server that answers both the Entra token request
// and the Graph sendMail call, so SendMail can be exercised end to end with
// no network. handler sees only the sendMail request.
func tokenAndSend(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3599}`))
			return
		}
		handler(w, r)
	}))
	c := New("tenant", "client", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL
	return c, srv
}

func validReq() SendMailRequest {
	return SendMailRequest{
		From:    "security@example.com",
		To:      []string{"operator@example.com"},
		Subject: "[CTI FLEET FAILED] cti-agent-digest.service",
		HTML:    "<html><body>it broke</body></html>",
	}
}

func TestSendMailPostsTheExpectedPayload(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var payload sendMailPayload
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotCT = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("request-id", "abc-123")
		w.WriteHeader(http.StatusAccepted) // sendMail answers 202, empty body
	})
	defer srv.Close()

	res, err := c.SendMail(context.Background(), validReq())
	if err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if res.RequestID != "abc-123" {
		t.Errorf("request-id = %q, wanted the header value back", res.RequestID)
	}
	// The status is reported rather than assumed. A caller that logs a
	// hardcoded 202 is describing the code, not the call.
	if res.Status != http.StatusAccepted {
		t.Errorf("status = %d, want %d", res.Status, http.StatusAccepted)
	}
	if want := "/users/security@example.com/sendMail"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if payload.Message.Body.ContentType != "HTML" {
		t.Errorf("contentType = %q, want HTML", payload.Message.Body.ContentType)
	}
	if len(payload.Message.ToRecipients) != 1 ||
		payload.Message.ToRecipients[0].EmailAddress.Address != "operator@example.com" {
		t.Errorf("recipients = %+v", payload.Message.ToRecipients)
	}
	if !payload.SaveToSentItems {
		t.Error("saveToSentItems should be true, so there is a record of what was sent")
	}
}

func TestSendMailImportanceIsOptIn(t *testing.T) {
	// A system that marks everything urgent has marked nothing urgent.
	for _, tc := range []struct {
		high bool
		want string
	}{{false, "normal"}, {true, "high"}} {
		var payload sendMailPayload
		c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&payload)
			w.WriteHeader(http.StatusAccepted)
		})
		req := validReq()
		req.HighImportance = tc.high
		if _, err := c.SendMail(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if payload.Message.Importance != tc.want {
			t.Errorf("HighImportance=%v gave importance %q, want %q",
				tc.high, payload.Message.Importance, tc.want)
		}
	}
}

func TestSendMailEscapesTheMailboxInThePath(t *testing.T) {
	// r.URL.Path is the DECODED path, so a correctly transmitted %20 appears
	// there as a literal space and an assertion on it fails against working
	// code. What actually matters is the raw request line, which is what the
	// $orderby bug corrupted: assert on RequestURI.
	var gotRequestURI, gotEscapedPath string
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI, gotEscapedPath = r.RequestURI, r.URL.EscapedPath()
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()
	req := validReq()
	req.From = "cyber security+team@example.com"
	if _, err := c.SendMail(context.Background(), req); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if strings.ContainsAny(gotRequestURI, " \t\r\n") {
		t.Errorf("unescaped whitespace reached the request line: %q", gotRequestURI)
	}
	if !strings.Contains(gotEscapedPath, "%20") {
		t.Errorf("space should have been percent-encoded, got %q", gotEscapedPath)
	}
}

func TestSendMailValidatesBeforeTouchingTheNetwork(t *testing.T) {
	var called bool
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()

	cases := map[string]func(*SendMailRequest){
		"no From":       func(r *SendMailRequest) { r.From = "" },
		"no recipients": func(r *SendMailRequest) { r.To = nil },
		"no subject":    func(r *SendMailRequest) { r.Subject = "" },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			req := validReq()
			mangle(&req)
			if _, err := c.SendMail(context.Background(), req); err == nil {
				t.Error("expected an error")
			}
			if called {
				t.Error("a request was sent despite invalid input")
			}
		})
	}
}

func TestSendMailErrorsAreDiagnostic(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		wantIn     string
	}{
		{"403 without policy detail names the permission", `{"error":{"code":"ErrorAccessDenied"}}`,
			403, "Mail.Send as an APPLICATION permission"},
		{"403 with REST detail names the mailbox licensing",
			`{"error":{"code":"MailboxNotEnabledForRESTAPI"}}`, 403, "REST-enabled mailbox"},
		{"404 names the address", `{"error":{"code":"ResourceNotFound"}}`,
			404, "not found"},
		{"anything else reports the status", `boom`, 500, "HTTP 500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			defer srv.Close()
			_, err := c.SendMail(context.Background(), validReq())
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error should mention %q, got: %v", tc.wantIn, err)
			}
		})
	}
}

func TestSendMailTruncatesHugeErrorBodies(t *testing.T) {
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	})
	defer srv.Close()
	_, err := c.SendMail(context.Background(), validReq())
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 900 {
		t.Errorf("error not truncated: %d chars", len(err.Error()))
	}
}

func TestSendMailSurfacesTokenFailures(t *testing.T) {
	// If Entra will not issue a token, say so rather than reporting a
	// confusing sendMail error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215"}`))
	}))
	defer srv.Close()
	c := New("tenant", "client", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL

	_, err := c.SendMail(context.Background(), validReq())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should identify the token step, got: %v", err)
	}
}

// CC, attachments and saveToSentItems were added for the mailer port. The
// recipient gate lives in internal/mailer; this only checks that what the
// caller asked for is what reaches the wire.
func TestSendMailCarriesCcAttachmentsAndSaveToSentItems(t *testing.T) {
	var payload map[string]any
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("request-id", "x")
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()

	no := false
	req := validReq()
	req.CC = []string{"cc1@example.com", "cc2@example.com"}
	req.Attachments = []Attachment{{
		Name: "raw.md", ContentType: "text/markdown", Bytes: []byte("hello"),
	}}
	req.SaveToSentItems = &no
	if _, err := c.SendMail(context.Background(), req); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	msg, _ := payload["message"].(map[string]any)
	cc, _ := msg["ccRecipients"].([]any)
	if len(cc) != 2 {
		t.Errorf("ccRecipients = %d, want 2", len(cc))
	}
	atts, _ := msg["attachments"].([]any)
	if len(atts) != 1 {
		t.Fatalf("attachments = %d, want 1", len(atts))
	}
	a, _ := atts[0].(map[string]any)
	// Graph rejects the message without the @odata.type discriminator, and
	// the failure is a 400 that does not say which field is wrong.
	if a["@odata.type"] != "#microsoft.graph.fileAttachment" {
		t.Errorf("@odata.type = %v", a["@odata.type"])
	}
	if a["contentBytes"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Errorf("contentBytes = %v, want base64 of the file", a["contentBytes"])
	}
	// A plain bool field would have made the zero value "do not save" and
	// silently changed what cti-alert does; the pointer keeps nil meaning true.
	if payload["saveToSentItems"] != false {
		t.Errorf("saveToSentItems = %v, want false when explicitly set",
			payload["saveToSentItems"])
	}
}

// nil means true - what every caller relied on before the field existed.
func TestSaveToSentItemsDefaultsToTrue(t *testing.T) {
	var payload map[string]any
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()

	if _, err := c.SendMail(context.Background(), validReq()); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if payload["saveToSentItems"] != true {
		t.Errorf("saveToSentItems = %v, want true when unset",
			payload["saveToSentItems"])
	}
}
