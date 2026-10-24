package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The loop this file exists to prevent:
//
// The digest is sent TO cybersecurity@, and the digest READS cybersecurity@.
// So yesterday's digest arrives as today's input, the extractor pulls the CVEs
// out of our own report, and they are presented as newly mentioned - every
// day, forever.
//
// It is self-sustaining: a CVE reported once re-enters every subsequent run,
// so the daily can never go quiet and the "emails mentioning a CVE" count is
// fiction. Observed 2026-10-04, where the only CVE-bearing email of the run
// was the previous day's own Sev5 digest.
//
// Nothing about it looked broken. The email was well-formed, the CVE was real,
// and every stage did exactly what it was written to do.

const fleetMailbox = "cybersecurity@example.com"

// messagesStub serves one page of Graph messages from the given raw JSON.
func messagesStub(t *testing.T, items string) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3599}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"value":[%s]}`, items)
	}))
	c := New("tenant", "client", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL
	return c, srv
}

func fetch(t *testing.T, items string) []Message {
	t.Helper()
	c, srv := messagesStub(t, items)
	defer srv.Close()
	msgs, err := c.RecentMessages(context.Background(), fleetMailbox, "inbox",
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("RecentMessages: %v", err)
	}
	return msgs
}

func TestOurOwnDigestIsRecognisedByItsHeader(t *testing.T) {
	// From a forwarding address, so only the header can identify it.
	msgs := fetch(t, `{
		"id":"1",
		"subject":"[Sev5] CTI Oct 03: 4 exploited vulns present in the environment",
		"receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"relay@example.com"}},
		"body":{"contentType":"HTML","content":"CVE-2026-94127"},
		"internetMessageHeaders":[{"name":"`+SelfHeader+`","value":"`+signSelfHeader("secret", fleetMailbox)+`"}]
	}`)

	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if !msgs[0].SelfSent || !msgs[0].SelfVerified {
		t.Errorf("the fleet's own signed digest: SelfSent=%v SelfVerified=%v",
			msgs[0].SelfSent, msgs[0].SelfVerified)
	}
}

func TestTheHeaderMatchIsCaseInsensitive(t *testing.T) {
	// Graph returns header names in whatever case the sending system used,
	// and Exchange does not promise to preserve ours.
	msgs := fetch(t, `{
		"id":"1","subject":"s","receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"relay@example.com"}},
		"body":{"contentType":"Text","content":""},
		"internetMessageHeaders":[{"name":"x-cti-agent-SENT","value":"`+signSelfHeader("secret", fleetMailbox)+`"}]
	}`)
	if !msgs[0].SelfVerified {
		t.Error("a lowercased header name was not matched")
	}
}

func TestAForgedHeaderIsIgnored(t *testing.T) {
	// The 1.2 header was the mailbox name and nothing else, and its mere
	// presence was enough: anyone mailing the inbox could have their message
	// skipped by the digest and archived by cti-mailbox.
	swapped := strings.Replace(signSelfHeader("secret", fleetMailbox),
		fleetMailbox, "other@example.com", 1)
	for name, value := range map[string]string{
		"the old bare form":     fleetMailbox,
		"anything at all":       "x",
		"a made-up signature":   fleetMailbox + "; n=00112233445566778899aabb; sig=deadbeef",
		"signed with other key": signSelfHeader("not-our-secret", fleetMailbox),
		"mailbox swapped":       swapped,
		"empty":                 "",
	} {
		msgs := fetch(t, `{
			"id":"1","subject":"Advisory","receivedDateTime":"2026-10-03T10:03:00Z",
			"from":{"emailAddress":{"address":"attacker@vendor.example"}},
			"body":{"contentType":"Text","content":"CVE-2026-1"},
			"internetMessageHeaders":[{"name":"`+SelfHeader+`","value":`+jsonString(value)+`}]
		}`)
		if msgs[0].SelfSent || msgs[0].SelfVerified {
			t.Errorf("%s: forged header accepted (SelfSent=%v SelfVerified=%v)",
				name, msgs[0].SelfSent, msgs[0].SelfVerified)
		}
	}
}

func TestTheSenderBackstopIsNeverVerified(t *testing.T) {
	// From is a claim the sender makes. It keeps old reports out of the
	// digest, but it must not be enough for cti-mailbox to move a message.
	msgs := fetch(t, `{
		"id":"1","subject":"[Sev5] CTI Oct 03","receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"`+fleetMailbox+`"}},
		"body":{"contentType":"HTML","content":"CVE-2026-94127"}
	}`)
	if !msgs[0].SelfSent {
		t.Error("mail from our own mailbox was not caught by the sender check")
	}
	if msgs[0].SelfVerified {
		t.Error("an unsigned message from our address was marked verified")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestOlderSelfSentMailIsCaughtByTheSender(t *testing.T) {
	// Everything already sitting in the mailbox was sent before SelfHeader
	// existed and carries no header at all. Without the sender backstop the
	// loop would keep running on the existing backlog for as long as the
	// lookback window reaches it - which is precisely the mail that caused
	// the bug.
	msgs := fetch(t, `{
		"id":"1","subject":"[Sev5] CTI Oct 03","receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"`+fleetMailbox+`"}},
		"body":{"contentType":"HTML","content":"CVE-2026-94127"}
	}`)
	if !msgs[0].SelfSent {
		t.Error("pre-header self-sent mail was not caught by the sender check")
	}
}

func TestTheSenderCheckIgnoresCase(t *testing.T) {
	msgs := fetch(t, `{
		"id":"1","subject":"s","receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"CyberSecurity@Example.COM"}},
		"body":{"contentType":"Text","content":""}
	}`)
	if !msgs[0].SelfSent {
		t.Error("a differently-cased copy of our own address was not matched")
	}
}

func TestARealAdvisoryIsNeverMarkedSelfSent(t *testing.T) {
	// The expensive failure in the other direction. This filter decides what
	// the digest is allowed to see, so a false positive here is a CVE that
	// silently never reaches anyone - the exact class of bug the rest of this
	// codebase is built to prevent.
	for name, from := range map[string]string{
		"a vendor":                   "CTI@vendor.example",
		"an operator forwarding":     "jeff@example.com",
		"a lookalike local part":     "cybersecurity@other.example",
		"a lookalike domain":         "cybersecurity@example.com.evil.example",
		"a longer local part":        "cybersecurity-reports@example.com",
		"the address as a substring": "notcybersecurity@example.com",
	} {
		msgs := fetch(t, `{
			"id":"1","subject":"Advisory","receivedDateTime":"2026-10-03T10:03:00Z",
			"from":{"emailAddress":{"address":"`+from+`"}},
			"body":{"contentType":"Text","content":"CVE-2026-1"}
		}`)
		if msgs[0].SelfSent {
			t.Errorf("%s (%s) was wrongly dropped as self-sent", name, from)
		}
	}
}

func TestAnEmptySenderIsNotTreatedAsOurs(t *testing.T) {
	// Graph omits "from" on a few message types. An empty-vs-empty comparison
	// would match and silently drop them.
	msgs := fetch(t, `{
		"id":"1","subject":"s","receivedDateTime":"2026-10-03T10:03:00Z",
		"body":{"contentType":"Text","content":"CVE-2026-1"}
	}`)
	if msgs[0].SelfSent {
		t.Error("a message with no sender was treated as self-sent")
	}
}

func TestSendMailStampsTheHeaderOnEverythingItSends(t *testing.T) {
	// The header is what makes the check above reliable rather than a guess
	// about addresses. If this stops being set, the sender backstop quietly
	// becomes the only defence and the forwarding cases start failing.
	var got sendMailPayload
	c, srv := tokenAndSend(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()

	if _, err := c.SendMail(context.Background(), validReq()); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	var found string
	for _, h := range got.Message.Headers {
		if strings.EqualFold(h.Name, SelfHeader) {
			found = h.Value
		}
	}
	if found == "" {
		t.Fatalf("outgoing mail carried no %s header: %+v", SelfHeader, got.Message.Headers)
	}
	if !strings.HasPrefix(found, validReq().From+"; n=") {
		t.Errorf("%s = %q, want the sending mailbox %q first", SelfHeader, found, validReq().From)
	}
	// tokenAndSend's client is built with its own secret; it must verify
	// against that and nothing else.
	if !verifySelfHeader(c.clientSecret, found) {
		t.Errorf("%s = %q does not verify with the sending client's secret", SelfHeader, found)
	}
	if verifySelfHeader(c.clientSecret+"x", found) {
		t.Errorf("%s verified with the wrong secret", SelfHeader)
	}
}

func TestTheHeaderNameIsValidForGraph(t *testing.T) {
	// Graph rejects the whole message if a custom header name does not begin
	// with "X-", and sendMail answers 202 for success, so a malformed header
	// would surface as mail that simply never arrives.
	if !strings.HasPrefix(SelfHeader, "X-") {
		t.Errorf("SelfHeader = %q, must start with X-", SelfHeader)
	}
}

func TestRecentMessagesHTMLAsksForAndKeepsTheHTMLBody(t *testing.T) {
	var prefer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3599}`))
			return
		}
		prefer = r.Header.Get("Prefer")
		_, _ = w.Write([]byte(`{"value":[{"id":"1","subject":"s","receivedDateTime":"2026-10-03T10:03:00Z",
			"from":{"emailAddress":{"address":"noreply@example.com"}},
			"body":{"contentType":"html","content":"<div>Scan Reference : was/1.2</div>"}}]}`))
	}))
	defer srv.Close()
	c := New("tenant", "client", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL
	msgs, err := c.RecentMessagesHTML(context.Background(), fleetMailbox, "inbox",
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(msgs) != 1 {
		t.Fatalf("msgs %v err %v", msgs, err)
	}
	if prefer != `outlook.body-content-type="html"` {
		t.Errorf("Prefer %q", prefer)
	}
	if msgs[0].BodyHTML != "<div>Scan Reference : was/1.2</div>" || msgs[0].BodyText != "" {
		t.Errorf("html %q text %q", msgs[0].BodyHTML, msgs[0].BodyText)
	}
	// The text reader is unchanged: whatever Graph labels it, it gets BodyText.
	if got := fetch(t, `{"id":"2","subject":"s","receivedDateTime":"2026-10-03T10:03:00Z",
		"from":{"emailAddress":{"address":"a@example.com"}},"body":{"contentType":"HTML","content":"x"}}`); got[0].BodyText != "x" {
		t.Errorf("text body %q", got[0].BodyText)
	}
}
