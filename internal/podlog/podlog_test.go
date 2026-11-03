package podlog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- test of the RFC 6455 accept hash.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// frame builds one unmasked server frame.
func frame(fin bool, op byte, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	switch n := len(payload); {
	case n < 126:
		out = append(out, byte(n))
	case n < 65536:
		out = append(out, 126, byte(n>>8), byte(n))
	default:
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		out = append(out, 127)
		out = append(out, l[:]...)
	}
	return append(out, payload...)
}

type stub struct {
	ln      net.Listener
	reqLine string
	headers http.Header
	pong    chan []byte
}

// newStub serves one connection: it answers the upgrade with status (101 for
// success) and then writes the frames.
func newStub(t *testing.T, status int, frames [][]byte) *stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stub{ln: ln, pong: make(chan []byte, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		s.reqLine = req.RequestURI
		s.headers = req.Header
		if status != 101 {
			_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID)) // #nosec G401
		_, _ = fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(sum[:]))
		for _, f := range frames {
			_, _ = c.Write(f)
		}
		// Read a possible pong back (masked client frame).
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(br, hdr); err == nil {
			n := int(hdr[1] & 0x7F)
			rest := make([]byte, 4+n)
			_, _ = io.ReadFull(br, rest)
			mask := rest[:4]
			data := rest[4:]
			for i := range data {
				data[i] ^= mask[i%4]
			}
			s.pong <- append([]byte{hdr[0]}, data...)
		}
	}()
	return s
}

func (s *stub) client() *Client {
	return &Client{Addr: s.ln.Addr().String(), plain: true, IdleTimeout: 2 * time.Second}
}

var good = Params{Cluster: "example_hosted", Token: "tok-secret", Type: "message"}

func collect(t *testing.T, c *Client, p Params) ([]string, error) {
	t.Helper()
	var got []string
	err := c.Stream(context.Background(), p, func(m []byte) error {
		got = append(got, string(m))
		return nil
	})
	return got, err
}

func TestStreamFragmentsPingLargeFrames(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 70000) // 64-bit length form
	mid := bytes.Repeat([]byte("y"), 300)   // 16-bit length form
	s := newStub(t, 101, [][]byte{
		frame(true, 0x1, []byte(`{"a":1}`)),
		frame(true, 0x9, []byte("hi")), // ping between messages
		frame(false, 0x1, []byte(`{"b":`)),
		frame(true, 0x0, []byte(`2}`)),
		frame(true, 0x1, mid),
		frame(true, 0x2, big),
		frame(true, 0x8, nil),
	})
	got, err := collect(t, s.client(), good)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF at close", err)
	}
	if len(got) != 4 || got[0] != `{"a":1}` || got[1] != `{"b":2}` || got[2] != string(mid) || len(got[3]) != 70000 {
		t.Fatalf("messages wrong: %d %q", len(got), got[:min(2, len(got))])
	}
	select {
	case p := <-s.pong:
		if p[0] != 0x8A || string(p[1:]) != "hi" {
			t.Fatalf("pong = %x %q", p[0], p[1:])
		}
	case <-time.After(time.Second):
		t.Fatal("no pong reply to the ping")
	}
}

func TestHandshakeSendsGuideHeadersAndQuery(t *testing.T) {
	s := newStub(t, 101, [][]byte{frame(true, 0x8, nil)})
	p := good
	p.Since = time.Date(2026, 11, 2, 10, 0, 0, 0, time.FixedZone("EST", -5*3600))
	p.To = p.Since.Add(time.Hour)
	_, _ = collect(t, s.client(), p)
	if got := s.headers.Get("Authorization"); got != "Bearer tok-secret" {
		t.Errorf("Authorization = %q", got)
	}
	if s.headers.Get("Upgrade") != "websocket" || s.headers.Get("Sec-WebSocket-Version") != "13" {
		t.Errorf("upgrade headers: %v", s.headers)
	}
	for _, want := range []string{"cid=example_hosted", "type=message", "sinceTime=2026-11-02T10%3A00%3A00-0500", "toTime=2026-11-02T11%3A00%3A00-0500"} {
		if !strings.Contains(s.reqLine, want) {
			t.Errorf("request %q lacks %q", s.reqLine, want)
		}
	}
	if s.headers.Get("Sec-WebSocket-Extensions") != "" {
		t.Error("the client must not ask for an extension")
	}
}

func TestStatusErrorsNameTheCauseNotTheToken(t *testing.T) {
	for code, want := range map[int]string{401: "licence", 409: "another session", 400: "malformed"} {
		s := newStub(t, code, nil)
		_, err := collect(t, s.client(), good)
		var se *StatusError
		if !errors.As(err, &se) || se.Code != code {
			t.Fatalf("code %d: err = %v", code, err)
		}
		if !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "tok-secret") {
			t.Errorf("code %d: error text %q", code, err.Error())
		}
	}
}

func TestExtensionBitIsRejected(t *testing.T) {
	f := frame(true, 0x1, []byte("x"))
	f[0] |= 0x40 // RSV1: what permessage-deflate would set
	s := newStub(t, 101, [][]byte{f})
	_, err := collect(t, s.client(), good)
	if err == nil || !strings.Contains(err.Error(), "extension") {
		t.Fatalf("err = %v", err)
	}
}

func TestMessageLimit(t *testing.T) {
	s := newStub(t, 101, [][]byte{frame(true, 0x1, bytes.Repeat([]byte("z"), 5000))})
	c := s.client()
	c.MaxMessage = 1000
	if _, err := collect(t, c, good); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestIdleTimeoutAndStop(t *testing.T) {
	s := newStub(t, 101, [][]byte{frame(true, 0x1, []byte("one"))})
	c := s.client()
	c.IdleTimeout = 150 * time.Millisecond
	if _, err := collect(t, c, good); !errors.Is(err, ErrIdle) {
		t.Fatalf("err = %v, want ErrIdle", err)
	}
	s = newStub(t, 101, [][]byte{frame(true, 0x1, []byte("one")), frame(true, 0x1, []byte("two"))})
	n := 0
	err := s.client().Stream(context.Background(), good, func([]byte) error { n++; return ErrStop })
	if err != nil || n != 1 {
		t.Fatalf("ErrStop: err=%v n=%d", err, n)
	}
}

func TestParamsValidation(t *testing.T) {
	bad := []Params{
		{Token: "t", Type: "message"},
		{Cluster: "c", Type: "message"},
		{Cluster: "c", Token: "t", Type: "other"},
		{Cluster: "c", Token: "a\r\nX: y", Type: "message"},
		{Cluster: "c", Token: "t", Type: "message", To: time.Now()},
		{Cluster: "c", Token: "t", Type: "message", Since: time.Now(), To: time.Now().Add(-time.Hour)},
	}
	for i, p := range bad {
		if err := p.validate(); err == nil {
			t.Errorf("case %d accepted: %+v", i, p)
		}
	}
	if err := good.validate(); err != nil {
		t.Errorf("good params rejected: %v", err)
	}
}

// All names, addresses and hosts below are invented.
const outboundEv = `{"ts":"2026-11-02T15:00:01.100000+0000","connection":{"ip":"192.0.2.10"},
"msg":{"header":{"from":["Sales <orders@example.com>"],"subject":["SECRET SUBJECT"],"to":["buyer@example.net"]},
"parsedAddresses":{"from":["orders@example.com"],"to":["buyer@example.net"]}},
"filter":{"qid":"Q1","routes":["allow_relay","mydomains_from_hdr"],"routeDirection":"outbound",
"modules":{"dmarc":{"filterdResult":"pass","authResults":[{"method":"spf","result":"pass"}]}}}}`

const spoofEv = `{"ts":"2026-11-02T15:05:00.000000+0000","connection":{"ip":"198.51.100.7"},
"msg":{"parsedAddresses":{"from":["ceo@example.com"]}},
"filter":{"qid":"Q2","routes":["default_inbound","mydomains_from_hdr"],"routeDirection":"inbound",
"modules":{"dmarc":{"filterdResult":"fail"},"spf":{"result":"softfail"}}}}`

const simEv = `{"ts":"2026-11-02T15:06:00.000000+0000","connection":{"ip":"203.0.113.9"},
"msg":{"parsedAddresses":{"from":["it@example.com"]}},
"filter":{"qid":"Q3","routes":["KnowBe4","default_inbound","mydomains_from_hdr"],"routeDirection":"inbound",
"modules":{"dmarc":{"filterdResult":"pass"}}}}`

const signedEv = `{"ts":"2026-11-02T15:07:00.000000+0000","connection":{"ip":"192.0.2.10"},
"msg":{"header":{"from":"News <news@example.org>"}},
"filter":{"qid":"Q4","routes":["allow_relay"],"routeDirection":"outbound",
"modules":{"dkimv":[{"domain":"example.org","selector":"s1","result":"pass"}]}}}`

func TestAggregate(t *testing.T) {
	a := NewAggregate()
	for _, e := range []string{outboundEv, spoofEv, simEv, signedEv} {
		a.AddMessage([]byte(e))
	}
	a.AddMessage([]byte(`{"ts":"2026-11-02T15:08:00.000000+0000"}`)) // no filter object
	a.AddMessage([]byte(`not json`))

	if a.Messages != 6 || a.Events != 5 || a.NoFilter != 1 || a.Undecoded != 1 {
		t.Fatalf("counts: %+v", a)
	}
	if a.Direction["outbound"] != 2 || a.Direction["inbound"] != 2 {
		t.Errorf("direction: %v", a.Direction)
	}
	if a.OutboundFrom["example.com"] != 1 || a.OutboundFrom["example.org"] != 1 {
		t.Errorf("outbound from: %v", a.OutboundFrom)
	}
	if a.OutboundIPs["192.0.2.10"] != 2 || a.OutboundWithDKIM != 1 || a.OutboundDKIM["example.org/s1/pass"] != 1 {
		t.Errorf("outbound ips/dkim: %v %d %v", a.OutboundIPs, a.OutboundWithDKIM, a.OutboundDKIM)
	}
	st := a.Spoof["example.com"]
	if st == nil || st.Total != 1 || st.DMARC["fail"] != 1 || a.SpoofIPs["198.51.100.7"] != 1 {
		t.Errorf("spoof: %+v %v", st, a.SpoofIPs)
	}
	if a.SimulatedCount != 1 || a.Spoof["example.com"].Total != 1 {
		t.Errorf("a simulation must be excluded from spoofing: sim=%d", a.SimulatedCount)
	}
	if a.SPF["pass"] != 1 || a.SPF["softfail"] != 1 {
		t.Errorf("spf (module, then dmarc authResults): %v", a.SPF)
	}
	if a.FirstTS != "2026-11-02T15:00:01Z" || a.LastTS != "2026-11-02T15:08:00Z" {
		t.Errorf("times: %s %s", a.FirstTS, a.LastTS)
	}
}

func TestReportHoldsNoMessageContent(t *testing.T) {
	a := NewAggregate()
	for _, e := range []string{outboundEv, spoofEv, simEv, signedEv} {
		a.AddMessage([]byte(e))
	}
	var b bytes.Buffer
	a.Report(&b, 20)
	for _, banned := range []string{"SECRET SUBJECT", "buyer@", "orders@", "ceo@", "news@", "@"} {
		if strings.Contains(b.String(), banned) {
			t.Errorf("report leaks %q:\n%s", banned, b.String())
		}
	}
}

func TestControlCharactersAndConcatenatedEvents(t *testing.T) {
	withCtl := strings.Replace(outboundEv, "SECRET SUBJECT", "SECRET\x01\n\tSUBJECT", 1)
	a := NewAggregate()
	a.AddMessage([]byte(withCtl))
	if a.Events != 1 || a.Undecoded != 0 || a.Messages != 1 {
		t.Fatalf("control characters: %+v", a)
	}
	b := NewAggregate()
	b.AddMessage([]byte(outboundEv + "\n" + signedEv))
	if b.Messages != 1 || b.Events != 2 {
		t.Fatalf("two events in one message: %+v", b)
	}
}

func TestKeyCapBoundsMemory(t *testing.T) {
	m := map[string]int{}
	for i := 0; i < MaxKeys+50; i++ {
		bump(m, fmt.Sprintf("k%d", i))
	}
	if len(m) != MaxKeys+1 || m[OverflowKey] != 50 {
		t.Fatalf("len=%d overflow=%d", len(m), m[OverflowKey])
	}
}

func TestFromDomainRejectsFreeText(t *testing.T) {
	ev := &event{}
	ev.Msg.ParsedAddresses.From = strList{"not an address @ bad host!"}
	if got := fromDomain(ev); got != "(unparsed)" {
		t.Errorf("got %q", got)
	}
	ev.Msg.ParsedAddresses.From = strList{"Name <a@Example.COM>"}
	if got := fromDomain(ev); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

func TestMaskedServerFrameIsRejected(t *testing.T) {
	f := frame(true, 0x1, []byte("x"))
	f[1] |= 0x80
	f = append(f[:2], append([]byte{1, 2, 3, 4}, f[2:]...)...)
	s := newStub(t, 101, [][]byte{f})
	if _, err := collect(t, s.client(), good); err == nil || !strings.Contains(err.Error(), "masked") {
		t.Fatalf("err = %v", err)
	}
}

func TestDroppedConnectionIsNotACleanClose(t *testing.T) {
	s := newStub(t, 101, [][]byte{frame(true, 0x1, []byte(`{"a":1}`))}) // no close frame
	got, err := collect(t, s.client(), good)
	if !errors.Is(err, ErrDropped) || len(got) != 1 {
		t.Fatalf("err=%v messages=%d", err, len(got))
	}
}
