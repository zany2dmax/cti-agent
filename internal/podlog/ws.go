// Package podlog reads Proofpoint on Demand's Log API and reduces it to
// aggregate counts.
//
// The vendor guide is "Proofpoint on Demand (PoD) Log API", Revision I, August
// 2023 (proprietary; see RUNBOOK 11g section 7 for what the fleet relies on).
// Where this package and the guide disagree, the guide wins.
//
// # WHY A HAND-WRITTEN WEBSOCKET CLIENT
//
// The service speaks plain RFC 6455 WebSocket and nothing else, and this
// module has no dependencies. The part of the protocol the Log API needs is
// small: one GET upgrade, then unmasked server frames (text, ping, close).
// So this is that part and no more: no extensions (the fleet never asks for
// permessage-deflate, so a frame with an RSV bit set is an error), no
// subprotocols, no sending of data. The only frames the client writes are the
// pong replies the protocol requires.
//
// # WHAT IT NEVER DOES
//
// It does not poll. The guide says polling can get the client locked out and
// that a token allows one session at a time (a second connection gets HTTP
// 409), so Stream makes exactly one connection per call and never retries.
// The token is never logged, never put in an error, and never accepted
// anywhere but the Authorization header.
package podlog

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 defines the accept hash as SHA-1; it is not a security control here.
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultAddr is the production endpoint (guide, "Endpoint").
	DefaultAddr = "logstream.proofpoint.com:443"

	// DefaultMaxMessage caps one reassembled message. Real events are large
	// (spam-engine signatures, URL lists) so the cap is generous, but a peer
	// that sends an endless message must not be able to exhaust memory.
	DefaultMaxMessage = 64 << 20

	// DefaultIdle is how long a read may wait for the next frame.
	DefaultIdle = 90 * time.Second

	// timeLayout is the guide's sinceTime/toTime format: ISO 8601 with a
	// numeric offset and no colon, for example 2018-01-25T02:37:40-0800.
	timeLayout = "2006-01-02T15:04:05-0700"

	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// ErrStop returned from the Stream callback ends the stream cleanly.
var ErrStop = errors.New("podlog: stop")

// ErrIdle means no frame arrived within the idle timeout.
var ErrIdle = errors.New("podlog: idle timeout")

// StatusError is a non-101 answer to the upgrade request. The guide's table:
// 400 malformed query, 401 bad token, cluster ID or licence, 404 bad URL or
// protocol, 405 not a GET, 409 token in use by another session.
type StatusError struct {
	Code   int
	Status string
}

func (e *StatusError) Error() string {
	hint := ""
	switch e.Code {
	case http.StatusBadRequest:
		hint = " (malformed query: cluster ID, type or time)"
	case http.StatusUnauthorized:
		hint = " (bad or expired token, wrong cluster ID, or no remote syslog licence)"
	case http.StatusConflict:
		hint = " (the token is already in use by another session)"
	}
	return fmt.Sprintf("pod log api: HTTP %s%s", e.Status, hint)
}

// Params selects what to read. Since and To are for archive reads only; leave
// both zero for the live feed. The service rounds Since down and To up to the
// hour and keeps 30 days.
type Params struct {
	Cluster string
	Token   string
	Type    string // message, maillog or audit
	Since   time.Time
	To      time.Time
}

func (p Params) validate() error {
	if strings.TrimSpace(p.Cluster) == "" {
		return errors.New("podlog: cluster ID is empty")
	}
	if p.Token == "" {
		return errors.New("podlog: token is empty")
	}
	if strings.ContainsAny(p.Token, "\r\n\x00 ") {
		return errors.New("podlog: token contains whitespace or control characters")
	}
	switch p.Type {
	case "message", "maillog", "audit":
	default:
		return fmt.Errorf("podlog: type %q is not message, maillog or audit", p.Type)
	}
	if !p.Since.IsZero() && !p.To.IsZero() && !p.To.After(p.Since) {
		return errors.New("podlog: To must be after Since")
	}
	if p.Since.IsZero() && !p.To.IsZero() {
		return errors.New("podlog: To needs Since")
	}
	return nil
}

func (p Params) requestURI() string {
	q := url.Values{}
	q.Set("cid", p.Cluster)
	q.Set("type", p.Type)
	if !p.Since.IsZero() {
		q.Set("sinceTime", p.Since.Format(timeLayout))
	}
	if !p.To.IsZero() {
		q.Set("toTime", p.To.Format(timeLayout))
	}
	return "/v1/stream?" + q.Encode()
}

// Client connects to the Log API. The zero value talks to production.
type Client struct {
	Addr        string      // host:port, default DefaultAddr
	TLSConfig   *tls.Config // nil means the system roots
	plain       bool        // no TLS; set only by this package's tests
	MaxMessage  int         // default DefaultMaxMessage
	IdleTimeout time.Duration
	DialTimeout time.Duration
}

func (c *Client) addr() string {
	if c.Addr != "" {
		return c.Addr
	}
	return DefaultAddr
}

// Stream opens one connection and calls fn for every complete message until
// the service closes the stream, fn returns ErrStop (nil is returned) or any
// other error, the context ends, or the connection stays idle too long
// (ErrIdle). The slice passed to fn is only valid during the call.
func (c *Client) Stream(ctx context.Context, p Params, fn func(msg []byte) error) error {
	if err := p.validate(); err != nil {
		return err
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	br := bufio.NewReaderSize(conn, 64<<10)
	if err := c.handshake(conn, br, p); err != nil {
		return err
	}
	err = c.readLoop(conn, br, fn)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	timeout := c.DialTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	if c.plain {
		return d.DialContext(ctx, "tcp", c.addr())
	}
	host, _, err := net.SplitHostPort(c.addr())
	if err != nil {
		return nil, fmt.Errorf("podlog: address %q: %w", c.addr(), err)
	}
	cfg := c.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}
	td := &tls.Dialer{NetDialer: d, Config: cfg}
	return td.DialContext(ctx, "tcp", c.addr())
}

func (c *Client) handshake(conn net.Conn, br *bufio.Reader, p Params) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("podlog: nonce: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req, err := http.NewRequest(http.MethodGet, "https://"+c.addr()+p.requestURI(), nil)
	if err != nil {
		return fmt.Errorf("podlog: request: %w", err)
	}
	req.Host = c.addr()
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("podlog: send upgrade: %w", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("podlog: read upgrade answer: %w", err)
	}
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return &StatusError{Code: resp.StatusCode, Status: resp.Status}
	}
	sum := sha1.Sum([]byte(key + wsGUID)) // #nosec G401 -- RFC 6455 accept hash.
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != base64.StdEncoding.EncodeToString(sum[:]) {
		return errors.New("podlog: Sec-WebSocket-Accept does not match the key sent")
	}
	if resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return errors.New("podlog: the service enabled an extension the client did not ask for")
	}
	return nil
}

func (c *Client) readLoop(conn net.Conn, br *bufio.Reader, fn func([]byte) error) error {
	limit := c.MaxMessage
	if limit <= 0 {
		limit = DefaultMaxMessage
	}
	idle := c.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdle
	}
	var msg []byte
	inFrag := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		fin, op, payload, err := readFrame(br, limit)
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout():
				return ErrIdle
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				return io.EOF
			}
			return err
		}
		switch op {
		case 0x8: // close
			_ = writeFrame(conn, 0x8, payload)
			return io.EOF
		case 0x9: // ping
			if err := writeFrame(conn, 0xA, payload); err != nil {
				return err
			}
		case 0xA: // pong
		case 0x1, 0x2, 0x0:
			if op == 0x0 {
				if !inFrag {
					return errors.New("podlog: continuation frame with nothing to continue")
				}
				if len(msg)+len(payload) > limit {
					return errors.New("podlog: message larger than the limit")
				}
				msg = append(msg, payload...)
			} else {
				if inFrag {
					return errors.New("podlog: new message started inside a fragmented one")
				}
				msg = append(msg[:0], payload...)
			}
			inFrag = !fin
			if fin {
				if err := fn(msg); err != nil {
					if errors.Is(err, ErrStop) {
						return nil
					}
					return err
				}
			}
		default:
			return fmt.Errorf("podlog: unknown frame opcode %#x", op)
		}
	}
}

// readFrame reads one frame. RFC 6455 forbids a masked server frame, so one is
// an error.
func readFrame(br *bufio.Reader, limit int) (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(br, h[:]); err != nil {
		return false, 0, nil, err
	}
	if h[0]&0x70 != 0 {
		return false, 0, nil, errors.New("podlog: frame uses an extension bit the client did not negotiate")
	}
	fin = h[0]&0x80 != 0
	op = h[0] & 0x0F
	if h[1]&0x80 != 0 {
		return false, 0, nil, errors.New("podlog: the server sent a masked frame")
	}
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return false, 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return false, 0, nil, err
		}
		v := binary.BigEndian.Uint64(b[:])
		if v > math.MaxInt32 {
			return false, 0, nil, errors.New("podlog: frame larger than the limit")
		}
		// #nosec G115 -- bounded by the MaxInt32 check above.
		n = int(v)
	}
	if op >= 0x8 && (n > 125 || !fin) {
		return false, 0, nil, errors.New("podlog: malformed control frame")
	}
	if n > limit {
		return false, 0, nil, errors.New("podlog: frame larger than the limit")
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(br, payload); err != nil {
		return false, 0, nil, err
	}
	return fin, op, payload, nil
}

// writeFrame sends one masked client frame (control frames only here).
func writeFrame(w io.Writer, op byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	if c, ok := w.(net.Conn); ok {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	out := make([]byte, 0, 6+len(payload))
	// #nosec G115 -- payload is capped at 125 above.
	out = append(out, 0x80|op, 0x80|byte(len(payload)))
	out = append(out, mask[:]...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	_, err := w.Write(out)
	return err
}
