// Package audit writes the fleet's audit trail: one RFC 5424 syslog line for
// every security-relevant action a command takes (a mail sent, a ticket
// filed, mail moved, an owner changed), who did it, to what, and how it
// came out.
//
// # WHY SYSLOG FORMAT
//
// RFC 5424 is the one format every log tool reads: rsyslog, syslog-ng, Splunk,
// Elastic, Wazuh, Azure Monitor and every SIEM take it without a parser to
// write. The file this package writes can be tailed by any of them, and the
// same line can be sent to a collector unchanged (see Forward). No SIEM is
// built here; this is the source one would read.
//
// # WHERE IT GOES
//
// /var/log/cti-agent/audit-YYYY-MM-DD.log (AUDIT_DIR), one file per UTC day,
// created by systemd (LogsDirectory=cti-agent) and 0640 or tighter. A daily
// file is the standard answer to rotation without a rotation daemon: the
// retention rule is "delete files older than N days" (Prune; the mailbox
// cleanup runs it, AUDIT_RETAIN_DAYS, default 120). If the directory cannot
// be written the line goes to stderr instead, which every unit sends to the
// journal, so an event is never silently lost and a missing directory never
// stops a lane from doing its work.
//
// # WHAT A LINE LOOKS LIKE
//
//	<86>1 2026-11-19T16:04:05.123Z host-a cti-jira 4242 jira.issue.create
//	  [audit@32473 v="1" lane="cti-jira" actor="ctiagent" run="b3f2..."
//	  target="CR-100" outcome="success"] filed a ticket
//
// (one line; wrapped here.) PRI 86 is facility authpriv, severity info;
// failures are warning (84), refusals notice (85). 32473 is the enterprise
// number RFC 5612 reserves for documentation; it names the structured-data
// block, nothing else. MSGID is the action. run is systemd's INVOCATION_ID
// (or FLEET_RUN_ID), so every line one unit run wrote shares a correlation id.
//
// # WHAT IS NEVER IN A LINE
//
// No message bodies, no credentials, no report text. Values are sanitised with
// safelog (a control character cannot start a forged line) and capped. A
// rehearsal (--dry-run) writes nothing, because nothing happened.
//
// # WHAT IT DOES NOT PROVE
//
// The writer is the same service account that runs the lanes, so a lane
// compromised as that account could alter the local file. The file is a record,
// not tamper-proof evidence; shipping it off the host (Forward, or a collector
// tailing the files) is what makes it evidence.
package audit

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// Outcomes. These are the only three; a command that cannot say which one it
// is has not finished.
const (
	Success = "success"
	Failure = "failure"
	Refused = "refused"
)

// DefaultDir is where the Fedora layout keeps the audit trail.
const DefaultDir = "/var/log/cti-agent"

// DefaultRetainDays is how long the cleanup keeps audit files.
const DefaultRetainDays = 120

// enterpriseID names the structured-data block. RFC 5612 reserves 32473 for
// documentation, so it collides with nobody's real number.
const enterpriseID = "32473"

const (
	facilityAuthpriv = 10
	sevNotice        = 5
	sevInfo          = 6
	sevWarning       = 4
)

// Event is one thing that was done.
type Event struct {
	Action  string // "jira.issue.create": becomes the MSGID
	Target  string // what it was done to: a ticket key, a mailbox, a recipient list
	Outcome string // Success, Failure or Refused
	Detail  string // a short safe note; never a body or a secret
}

// Logger writes events. Use FromEnv, or build one in a test.
type Logger struct {
	Dir   string // "" means DefaultDir; "off" discards the file and the stderr fallback
	Lane  string
	Actor string
	Run   string
	Host  string
	Pid   int

	// Forward, when set, sends every line to a syslog collector as well.
	Forward *Forwarder

	Now  func() time.Time
	Warn io.Writer // where a problem writing is reported; stderr when nil

	mu     sync.Mutex
	warned map[string]bool
}

// FromEnv builds the logger a command uses: AUDIT_DIR, AUDIT_SYSLOG_ADDR,
// AUDIT_SYSLOG_PROTO, FLEET_RUN_ID or systemd's INVOCATION_ID, and the
// process name as the lane.
func FromEnv() *Logger {
	host, _ := os.Hostname()
	l := &Logger{
		Dir:   strings.TrimSpace(os.Getenv("AUDIT_DIR")),
		Lane:  filepath.Base(os.Args[0]),
		Actor: actor(),
		Run:   runID(),
		Host:  host,
		Pid:   os.Getpid(),
		Now:   time.Now,
	}
	if addr := strings.TrimSpace(os.Getenv("AUDIT_SYSLOG_ADDR")); addr != "" {
		l.Forward = &Forwarder{Addr: addr, Proto: strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_SYSLOG_PROTO")))}
	}
	return l
}

func actor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	// sudo cti-agent runs as the service account but a person typed it.
	if s := strings.TrimSpace(os.Getenv("SUDO_USER")); s != "" && s != name {
		name += " (via sudo, " + s + ")"
	}
	return name
}

func runID() string {
	for _, k := range []string{"FLEET_RUN_ID", "INVOCATION_ID"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

var (
	stdOnce sync.Once
	std     *Logger
)

// SetDefault replaces the process-wide logger and returns a function that
// puts the old one back. It is for tests, which need to read what a client
// wrote or to keep events out of the real trail.
func SetDefault(l *Logger) (restore func()) {
	stdOnce.Do(func() { std = FromEnv() })
	old := std
	std = l
	return func() { std = old }
}

// Emit writes one event with the process-wide logger. It never fails the
// caller: a problem writing is reported on stderr and the lane carries on.
func Emit(e Event) {
	stdOnce.Do(func() { std = FromEnv() })
	_ = std.Emit(e)
}

// Emit writes one event. The error is for tests and for cti-audit --check; a
// command in the middle of its work ignores it, because an unwritable log
// must not stop the mail from going out or the ticket from being filed. The
// problem is reported once per kind, on Warn.
func (l *Logger) Emit(e Event) error {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	t := now().UTC()
	line := l.Format(t, e)

	var firstErr error
	note := func(kind string, err error) {
		if firstErr == nil {
			firstErr = err
		}
		l.warn(kind, err)
	}

	switch dir := l.dir(); dir {
	case "off":
		// Discarded on purpose (tests, a dev machine).
	default:
		if err := writeFile(dir, t, line); err != nil {
			note("file", fmt.Errorf("audit: cannot write %s (%v); the event follows on stderr, which the journal keeps", dir, err))
			_, _ = fmt.Fprintln(l.warnOut(), line)
		}
	}
	if l.Forward != nil && l.dir() != "off" {
		if err := l.Forward.Send(line); err != nil {
			note("forward", fmt.Errorf("audit: cannot forward to %s (%v); the local file still has it", l.Forward.Addr, err))
		}
	}
	return firstErr
}

func (l *Logger) dir() string {
	if l.Dir == "" {
		return DefaultDir
	}
	return l.Dir
}

func (l *Logger) warnOut() io.Writer {
	if l.Warn != nil {
		return l.Warn
	}
	return os.Stderr
}

// warn reports a problem once per kind per process: a dead collector must not
// print a line for every one of a thousand events.
func (l *Logger) warn(kind string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.warned == nil {
		l.warned = map[string]bool{}
	}
	if l.warned[kind] {
		return
	}
	l.warned[kind] = true
	_, _ = fmt.Fprintln(l.warnOut(), err.Error())
}

func writeFile(dir string, t time.Time, line string) error {
	path := filepath.Join(dir, "audit-"+t.Format("2006-01-02")+".log")
	// O_NOFOLLOW: a symlink planted where the day's file goes must not
	// redirect the audit trail.
	// #nosec G304 G302 -- the directory is ours (AUDIT_DIR or /var/log/cti-agent); 0640 is the intent, the unit's UMask only tightens it
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return err
	}
	// One Write of one line: O_APPEND makes that atomic for a line this size,
	// so concurrent units do not interleave.
	_, werr := f.WriteString(line + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Format renders the RFC 5424 line for an event, without the trailing newline.
func (l *Logger) Format(t time.Time, e Event) string {
	e.Outcome = outcome(e.Outcome) // severity follows what is recorded, not what was passed
	sev := sevInfo
	switch e.Outcome {
	case Failure:
		sev = sevWarning
	case Refused:
		sev = sevNotice
	}
	pri := facilityAuthpriv*8 + sev

	lane := token(l.Lane, 48, "cti-agent")
	host := token(l.Host, 255, "-")
	pid := "-"
	if l.Pid > 0 {
		pid = strconv.Itoa(l.Pid)
	}
	msgid := msgID(e.Action)

	var sd strings.Builder
	sd.WriteString("[audit@" + enterpriseID + ` v="1"`)
	for _, kv := range [][2]string{
		{"lane", lane},
		{"actor", l.Actor},
		{"run", l.Run},
		{"target", e.Target},
		{"outcome", e.Outcome},
	} {
		sd.WriteString(" " + kv[0] + `="` + sdValue(kv[1], 256) + `"`)
	}
	sd.WriteString("]")

	msg := safelog.LineMax(e.Detail, 300)
	if msg == "" {
		msg = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		pri, t.UTC().Format("2006-01-02T15:04:05.000Z"), host, lane, pid, msgid, sd.String(), msg)
}

var msgidBad = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// msgID is the action, restricted to what RFC 5424 allows (printable ASCII, no
// spaces, at most 32 characters).
func msgID(action string) string {
	a := msgidBad.ReplaceAllString(strings.TrimSpace(action), "_")
	if a == "" {
		return "-"
	}
	if len(a) > 32 {
		a = a[:32]
	}
	return a
}

func outcome(o string) string {
	switch o {
	case Success, Failure, Refused:
		return o
	}
	return Failure // an event that does not say how it ended did not end well
}

// token makes a header field: printable ASCII, no spaces, capped; fallback if
// nothing is left.
func token(s string, max int, fallback string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	if b.Len() == 0 {
		return fallback
	}
	return b.String()
}

// sdValue makes a structured-data parameter value: sanitised (no control or
// invisible characters), capped, and with the three characters RFC 5424 says
// to escape (the quote, the backslash and the closing bracket) escaped.
func sdValue(s string, max int) string {
	s = safelog.LineMax(s, max)
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '\\', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---- forwarding ------------------------------------------------------------

// Forwarder sends a line to a syslog collector. It is the SIEM option: off
// unless AUDIT_SYSLOG_ADDR is set, and nothing here knows which product is on
// the other end.
//
// Proto is tls (the default: RFC 5425, certificate and hostname verified,
// TLS 1.2 minimum), tcp, or udp. tls and tcp use RFC 6587 octet counting, so a
// line with odd characters cannot be split into two records; udp sends one
// datagram per line. A plaintext proto has to be asked for by name.
type Forwarder struct {
	Addr    string // host:port
	Proto   string // tls (default), tcp, udp
	Timeout time.Duration
}

// Send delivers one line. Every call dials afresh: events are few, and a
// connection held open for hours is a connection that is dead when needed.
func (f *Forwarder) Send(line string) error {
	conn, proto, timeout, err := f.dial()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	payload := line
	if proto != "udp" {
		payload = strconv.Itoa(len(line)) + " " + line
	}
	_, err = io.WriteString(conn, payload)
	return err
}

// Probe connects and hangs up without sending an event, for cti-audit --check.
// For udp there is nothing to connect to, so it only checks the address.
func (f *Forwarder) Probe() error {
	conn, _, _, err := f.dial()
	if err != nil {
		return err
	}
	return conn.Close()
}

func (f *Forwarder) dial() (net.Conn, string, time.Duration, error) {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	proto := f.Proto
	if proto == "" {
		proto = "tls"
	}
	host, _, err := net.SplitHostPort(f.Addr)
	if err != nil {
		return nil, "", 0, fmt.Errorf("AUDIT_SYSLOG_ADDR must be host:port: %w", err)
	}
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	switch proto {
	case "tls":
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
		conn, err = td.Dial("tcp", f.Addr)
	case "tcp":
		conn, err = d.Dial("tcp", f.Addr)
	case "udp":
		conn, err = d.Dial("udp", f.Addr)
	default:
		return nil, "", 0, fmt.Errorf("AUDIT_SYSLOG_PROTO %q is not tls, tcp or udp", f.Proto)
	}
	if err != nil {
		return nil, "", 0, err
	}
	return conn, proto, timeout, nil
}

// ---- retention -------------------------------------------------------------

var auditFile = regexp.MustCompile(`^audit-(\d{4}-\d{2}-\d{2})\.log$`)

// Prune deletes audit files whose UTC date is more than keepDays old, and
// returns their names. It touches only regular files named audit-DATE.log in
// dir: a symlink, a directory or any other name is left alone. With dry set it
// deletes nothing and returns what it would.
func Prune(dir string, keepDays int, now time.Time, dry bool) ([]string, error) {
	if keepDays < 1 {
		return nil, errors.New("audit: keep at least 1 day")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	cutoff := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -keepDays)
	var gone []string
	for _, e := range entries {
		m := auditFile.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		day, err := time.Parse("2006-01-02", m[1])
		if err != nil || !day.Before(cutoff) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if !dry {
			if err := os.Remove(path); err != nil {
				return gone, err
			}
		}
		gone = append(gone, e.Name())
	}
	return gone, nil
}
