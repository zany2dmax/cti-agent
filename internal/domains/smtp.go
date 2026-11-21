package domains

import (
	"context"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SMTPResult is the original checker's -smtp banner probe, plus whether the
// server offers STARTTLS - mail to a domain whose MX does not is readable by
// anyone on the path.
type SMTPResult struct {
	Checked  bool
	Host     string
	Port     int
	Banner   string
	StartTLS bool
	Err      string
}

// SMTPProber probes one MX host. A field so tests can replace the network.
type SMTPProber func(ctx context.Context, host string) SMTPResult

// NetSMTPProber connects, reads the 220 greeting, sends EHLO, reads the
// extensions, and QUITs. It never sends MAIL FROM: this is a greeting, not a
// delivery attempt, and it is what any MTA would see before deciding.
func NetSMTPProber(port int, timeout time.Duration, resolver *net.Resolver, allowPrivate bool) SMTPProber {
	return func(ctx context.Context, host string) SMTPResult {
		res := SMTPResult{Checked: true, Host: host, Port: port}
		d := dialer(timeout, resolver, allowPrivate)
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			res.Err = shortNetErr(err)
			return res
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * timeout))
		// A real greeting and EHLO reply are a few hundred bytes. A hostile MX
		// can send forever, so the connection is cut off after a generous cap
		// (the deadline alone bounds time, not bytes).
		tp := textproto.NewConn(&capConn{Conn: conn, left: maxSMTPBytes})
		_, msg, err := tp.ReadResponse(220)
		if err != nil {
			res.Err = "no SMTP greeting: " + shortNetErr(err)
			return res
		}
		res.Banner = firstLine(msg)
		id, err := tp.Cmd("EHLO cti-agent.invalid")
		if err != nil {
			res.Err = "EHLO not sent: " + shortNetErr(err)
			return res
		}
		tp.StartResponse(id)
		_, ext, err := tp.ReadResponse(250)
		tp.EndResponse(id)
		if err != nil {
			res.Err = "EHLO refused: " + shortNetErr(err)
			return res
		}
		for _, l := range strings.Split(ext, "\n") {
			if strings.EqualFold(strings.Fields(l + " x")[0], "STARTTLS") {
				res.StartTLS = true
			}
		}
		_, _ = tp.Cmd("QUIT")
		return res
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120]) + "..."
	}
	return s
}

// SMTPBlocked reports whether every SMTP probe this run failed to connect at
// all - the signature of outbound port 25 being closed from the probing host,
// not of every mail server being down. Needs at least three domains probed so
// one dead MX on a one-domain run is not read as a firewall. Counted by domain,
// not by MX host: a portfolio behind one gateway has only two or three hosts.
func SMTPBlocked(results []Result) bool {
	n := 0
	for _, r := range results {
		s := r.Mail.SMTP
		if !s.Checked {
			continue
		}
		if s.Err == "" {
			return false
		}
		n++
	}
	return n >= 3
}

// smtpCache dials each MX host once per run. Ninety domains behind the same
// mail gateway would otherwise be ninety connections to it in a minute, which
// is both rude and the pattern that gets a scanning host blocklisted.
type smtpCache struct {
	probe SMTPProber
	mu    sync.Mutex
	done  map[string]*smtpEntry
}

type smtpEntry struct {
	once sync.Once
	res  SMTPResult
}

func newSMTPCache(p SMTPProber) *smtpCache {
	return &smtpCache{probe: p, done: map[string]*smtpEntry{}}
}

func (c *smtpCache) get(ctx context.Context, host string) SMTPResult {
	c.mu.Lock()
	e, ok := c.done[host]
	if !ok {
		e = &smtpEntry{}
		c.done[host] = e
	}
	c.mu.Unlock()
	// WithoutCancel: the first caller's per-domain budget may be nearly spent on
	// web probes, and a timeout here is cached for every domain sharing the MX.
	// The prober applies its own timeout.
	e.once.Do(func() { e.res = c.probe(context.WithoutCancel(ctx), host) })
	return e.res
}

// maxSMTPBytes is the most read from one MX host's SMTP session.
const maxSMTPBytes = 64 << 10

// maxMXProbed is the most MX hosts tried for one domain. Real domains publish
// two to five; a name whose DNS lists hundreds is one built to keep the run
// busy, and the run's deadline is the whole lane's.
const maxMXProbed = 8

// capConn reads at most left bytes and then reports EOF.
type capConn struct {
	net.Conn
	left int64
}

func (c *capConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= int64(n)
	return n, err
}

// first probes MX hosts in preference order and returns the first that
// greeted, or the last failure. Unresolvable hosts are skipped.
func (c *smtpCache) first(ctx context.Context, hosts, unresolved []string) SMTPResult {
	skip := map[string]bool{}
	for _, h := range unresolved {
		skip[h] = true
	}
	var last SMTPResult
	tried := 0
	for _, h := range hosts {
		if h == "." || skip[h] {
			continue
		}
		// The first caller's budget for this domain, not the shared cache's:
		// c.get runs without the caller's cancellation (a timeout there would
		// be cached for every domain on that MX), so the walk itself has to
		// stop when the domain's time is spent.
		if tried >= maxMXProbed || ctx.Err() != nil {
			break
		}
		tried++
		r := c.get(ctx, h)
		if r.Err == "" {
			return r
		}
		last = r
	}
	return last
}
