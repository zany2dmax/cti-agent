package audit

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var fixed = time.Date(2026, 11, 19, 16, 4, 5, 123_000_000, time.UTC)

func logger(dir string) (*Logger, *strings.Builder) {
	var warn strings.Builder
	return &Logger{
		Dir: dir, Lane: "cti-jira", Actor: "ctiagent", Run: "run-1",
		Host: "host-a", Pid: 4242, Now: func() time.Time { return fixed }, Warn: &warn,
	}, &warn
}

// RFC 5424: <PRI>1 TS HOST APP PROCID MSGID SD MSG
var rfc5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (\S+) (\S+) (\S+) (\S+) (\[.*\]|-) (.*)$`)

func TestLineIsRFC5424(t *testing.T) {
	l, _ := logger(t.TempDir())
	line := l.Format(fixed, Event{Action: "jira.issue.create", Target: "CR-100", Outcome: Success, Detail: "filed a ticket"})
	m := rfc5424.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("not RFC 5424: %q", line)
	}
	if m[1] != "86" { // authpriv (10*8) + info (6)
		t.Errorf("PRI = %s, want 86", m[1])
	}
	if m[2] != "2026-11-19T16:04:05.123Z" || m[3] != "host-a" || m[4] != "cti-jira" || m[5] != "4242" || m[6] != "jira.issue.create" {
		t.Errorf("header fields wrong: %v", m[1:7])
	}
	for _, want := range []string{`[audit@32473 v="1"`, `lane="cti-jira"`, `actor="ctiagent"`, `run="run-1"`, `target="CR-100"`, `outcome="success"`} {
		if !strings.Contains(m[7], want) {
			t.Errorf("structured data lacks %s: %s", want, m[7])
		}
	}
	if m[8] != "filed a ticket" {
		t.Errorf("MSG = %q", m[8])
	}
}

func TestSeverityFollowsTheOutcome(t *testing.T) {
	l, _ := logger(t.TempDir())
	for outcome, pri := range map[string]string{Success: "<86>", Failure: "<84>", Refused: "<85>", "": "<84>", "banana": "<84>"} {
		line := l.Format(fixed, Event{Action: "a", Outcome: outcome})
		if !strings.HasPrefix(line, pri) {
			t.Errorf("outcome %q: %q does not start %s", outcome, line, pri)
		}
	}
	// An event that does not say how it ended is recorded as a failure.
	if got := l.Format(fixed, Event{Action: "a", Outcome: "banana"}); !strings.Contains(got, `outcome="failure"`) {
		t.Errorf("unknown outcome was not recorded as failure: %s", got)
	}
}

// A value that came from outside (a subject, a recipient, an error text) must
// not be able to end the structured data, add a parameter, or start a new line.
func TestHostileValuesCannotForgeARecord(t *testing.T) {
	l, _ := logger(t.TempDir())
	evil := "x\"] [audit@32473 outcome=\"success\" \nINJECTED <86>1 forged\r\x1b[31m\\"
	line := l.Format(fixed, Event{Action: "mail.send\nINJECT", Target: evil, Outcome: Failure, Detail: evil})
	if strings.ContainsAny(line, "\n\r\x1b") {
		t.Fatalf("a control character survived: %q", line)
	}
	m := rfc5424.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("the line stopped being RFC 5424: %q", line)
	}
	// Parse the structured data the way a collector does: it ends at the first
	// ] that is not escaped. Everything after is the free-text message.
	rest := line[strings.Index(line, "[audit@"):]
	end := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' {
			i++
			continue
		}
		if rest[i] == ']' {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatalf("structured data never closes: %q", rest)
	}
	sd := rest[:end+1]
	// A "[" inside a quoted value is legal (only quote, backslash and ] are
	// escaped); what matters is that the element ends at OUR outcome.
	if strings.Count(sd, ` outcome="`) != 1 || !strings.HasSuffix(strings.TrimSuffix(sd, "]"), `outcome="failure"`) {
		t.Errorf("a value added or replaced the outcome parameter: %s", sd)
	}
	if !strings.Contains(sd, `\"`) || !strings.Contains(sd, `\]`) || !strings.Contains(sd, `\\`) {
		t.Errorf("quote, bracket or backslash not escaped: %s", sd)
	}
	if strings.ContainsAny(m[6], " \n") || len(m[6]) > 32 {
		t.Errorf("MSGID %q breaks the format", m[6])
	}
}

func TestHeaderFieldsAreCappedAndSpaceFree(t *testing.T) {
	l, _ := logger(t.TempDir())
	l.Lane = "my lane\nwith space " + strings.Repeat("x", 100)
	l.Host = ""
	l.Pid = 0
	line := l.Format(fixed, Event{Action: strings.Repeat("a", 80)})
	m := rfc5424.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("not RFC 5424: %q", line)
	}
	if m[3] != "-" || m[5] != "-" || len(m[4]) > 48 || len(m[6]) != 32 {
		t.Errorf("header fields: host=%q app=%q procid=%q msgid=%q", m[3], m[4], m[5], m[6])
	}
}

func TestEmitAppendsOneLinePerEventToTheDaysFile(t *testing.T) {
	dir := t.TempDir()
	l, warn := logger(dir)
	for _, a := range []string{"one", "two"} {
		if err := l.Emit(Event{Action: a, Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit-2026-11-19.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], " one ") || !strings.Contains(lines[1], " two ") {
		t.Fatalf("file = %q", b)
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warning: %s", warn.String())
	}
	// The next day goes to the next file.
	l.Now = func() time.Time { return fixed.Add(24 * time.Hour) }
	_ = l.Emit(Event{Action: "three", Outcome: Success})
	if _, err := os.Stat(filepath.Join(dir, "audit-2026-11-20.log")); err != nil {
		t.Errorf("no file for the next day: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "audit-2026-11-19.log")); fi.Mode().Perm()&0o027 != 0 {
		t.Errorf("file mode %v is looser than 0640", fi.Mode().Perm())
	}
}

// An unwritable directory must not stop a lane, and must not lose the event.
func TestUnwritableDirFallsBackToStderrOnce(t *testing.T) {
	l, warn := logger(filepath.Join(t.TempDir(), "does", "not", "exist"))
	for i := 0; i < 3; i++ {
		if err := l.Emit(Event{Action: "mail.send", Target: "x", Outcome: Success}); err == nil {
			t.Fatal("want the write error back, for --check")
		}
	}
	out := warn.String()
	if strings.Count(out, "cannot write") != 1 {
		t.Errorf("the problem should be reported once, got:\n%s", out)
	}
	if strings.Count(out, "mail.send") != 3 {
		t.Errorf("each event should still reach stderr:\n%s", out)
	}
}

func TestOffDiscardsEverything(t *testing.T) {
	l, warn := logger("off")
	if err := l.Emit(Event{Action: "a", Outcome: Success}); err != nil || warn.Len() != 0 {
		t.Fatalf("off should be silent: %v %q", err, warn.String())
	}
}

func TestASymlinkWhereTheDaysFileGoesIsRefused(t *testing.T) {
	dir, elsewhere := t.TempDir(), filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(elsewhere, filepath.Join(dir, "audit-2026-11-19.log")); err != nil {
		t.Skip("no symlinks here")
	}
	l, _ := logger(dir)
	if err := l.Emit(Event{Action: "a", Outcome: Success}); err == nil {
		t.Fatal("followed a symlink")
	}
	if _, err := os.Stat(elsewhere); err == nil {
		t.Fatal("wrote through the symlink")
	}
}

func TestRunIDComesFromTheEnvironment(t *testing.T) {
	t.Setenv("FLEET_RUN_ID", "")
	t.Setenv("INVOCATION_ID", "systemd-inv")
	if r := runID(); r != "systemd-inv" {
		t.Errorf("run = %q", r)
	}
	t.Setenv("FLEET_RUN_ID", "explicit")
	if r := runID(); r != "explicit" {
		t.Errorf("FLEET_RUN_ID should win, got %q", r)
	}
	t.Setenv("FLEET_RUN_ID", "")
	t.Setenv("INVOCATION_ID", "")
	if r := runID(); len(r) != 16 {
		t.Errorf("generated id %q should be 16 hex characters", r)
	}
}

func TestFromEnvReadsTheSettings(t *testing.T) {
	t.Setenv("AUDIT_DIR", "/tmp/x")
	t.Setenv("AUDIT_SYSLOG_ADDR", "collector.example.com:6514")
	t.Setenv("AUDIT_SYSLOG_PROTO", "TCP")
	l := FromEnv()
	if l.Dir != "/tmp/x" || l.Forward == nil || l.Forward.Addr != "collector.example.com:6514" || l.Forward.Proto != "tcp" {
		t.Fatalf("%+v %+v", l, l.Forward)
	}
	t.Setenv("AUDIT_SYSLOG_ADDR", "")
	if FromEnv().Forward != nil {
		t.Fatal("forwarding must be off unless AUDIT_SYSLOG_ADDR is set")
	}
}

// ---- forwarding ----

func TestForwardTCPUsesOctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	l, _ := logger(t.TempDir())
	l.Forward = &Forwarder{Addr: ln.Addr().String(), Proto: "tcp"}
	if err := l.Emit(Event{Action: "mail.send", Target: "x", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		sp := strings.Index(s, " ")
		n, err := strconv.Atoi(s[:sp])
		if err != nil || n != len(s)-sp-1 {
			t.Fatalf("octet count wrong: %q", s)
		}
		if rfc5424.FindStringSubmatch(s[sp+1:]) == nil {
			t.Fatalf("payload is not RFC 5424: %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector got nothing")
	}
}

func TestForwardUDPSendsTheBareLine(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = pc.Close() }()
	l, _ := logger(t.TempDir())
	l.Forward = &Forwarder{Addr: pc.LocalAddr().String(), Proto: "udp"}
	if err := l.Emit(Event{Action: "mail.send", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if rfc5424.FindStringSubmatch(string(buf[:n])) == nil {
		t.Fatalf("datagram is not the bare RFC 5424 line: %q", buf[:n])
	}
}

// A collector that is down must cost the lane nothing but a warning, and the
// local file still has the event.
func TestDeadCollectorIsAWarningNotAFailure(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens here now
	dir := t.TempDir()
	l, warn := logger(dir)
	l.Forward = &Forwarder{Addr: addr, Proto: "tcp", Timeout: time.Second}
	for i := 0; i < 3; i++ {
		_ = l.Emit(Event{Action: "a", Outcome: Success})
	}
	if strings.Count(warn.String(), "cannot forward") != 1 {
		t.Errorf("want one warning, got %q", warn.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "audit-2026-11-19.log"))
	if strings.Count(string(b), "\n") != 3 {
		t.Errorf("local file lost events: %q", b)
	}
}

func TestTLSForwardRefusesAPlaintextCollector(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = bufio.NewReader(c).ReadString('\n') // never speaks TLS
			_ = c.Close()
		}
	}()
	f := &Forwarder{Addr: ln.Addr().String(), Timeout: time.Second} // proto defaults to tls
	if err := f.Send("x"); err == nil {
		t.Fatal("the default proto must be tls, and a plaintext peer must fail it")
	}
}

func TestForwarderRejectsBadSettings(t *testing.T) {
	if err := (&Forwarder{Addr: "no-port"}).Send("x"); err == nil {
		t.Error("an address without a port was accepted")
	}
	if err := (&Forwarder{Addr: "127.0.0.1:1", Proto: "carrier-pigeon"}).Send("x"); err == nil {
		t.Error("an unknown proto was accepted")
	}
}

// ---- retention ----

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestPruneKeepsTheWindowAndOnlyAuditFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 19, 7, 0, 0, 0, time.UTC)
	for _, n := range []string{
		"audit-2026-11-19.log", // today
		"audit-2026-07-22.log", // exactly 120 days old: kept
		"audit-2026-07-21.log", // 121 days old: deleted
		"audit-2025-01-01.log", // deleted
		"audit-2020-01-01.log.gz",
		"messages.log",
		"audit-2020-13-45.log",
		"notes.txt",
	} {
		touch(t, dir, n)
	}
	gone, err := Prune(dir, 120, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 2 {
		t.Fatalf("pruned %v, want the two old audit files", gone)
	}
	for _, n := range []string{"audit-2026-11-19.log", "audit-2026-07-22.log", "audit-2020-01-01.log.gz", "messages.log", "audit-2020-13-45.log", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s should have been left alone: %v", n, err)
		}
	}
	for _, n := range []string{"audit-2026-07-21.log", "audit-2025-01-01.log"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s should have been deleted", n)
		}
	}
}

func TestPruneDryRunDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "audit-2020-01-01.log")
	gone, err := Prune(dir, 120, time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), true)
	if err != nil || len(gone) != 1 {
		t.Fatalf("%v %v", gone, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-2020-01-01.log")); err != nil {
		t.Fatal("dry run deleted the file")
	}
}

func TestPruneNeverFollowsASymlinkOrTouchesADirectory(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	touch(t, other, "precious")
	if err := os.Symlink(filepath.Join(other, "precious"), filepath.Join(dir, "audit-2020-01-01.log")); err != nil {
		t.Skip("no symlinks here")
	}
	if err := os.Mkdir(filepath.Join(dir, "audit-2020-02-02.log"), 0o750); err != nil {
		t.Fatal(err)
	}
	gone, err := Prune(dir, 120, time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), false)
	if err != nil || len(gone) != 0 {
		t.Fatalf("pruned %v (%v): a symlink or directory was treated as a log", gone, err)
	}
	if _, err := os.Stat(filepath.Join(other, "precious")); err != nil {
		t.Fatal("the symlink target was deleted")
	}
}

func TestPruneRefusesNonsenseWindows(t *testing.T) {
	for _, d := range []int{0, -5} {
		if _, err := Prune(t.TempDir(), d, time.Now(), false); err == nil {
			t.Errorf("keepDays=%d accepted", d)
		}
	}
	if _, err := Prune(filepath.Join(t.TempDir(), "nope"), 120, time.Now(), false); err == nil {
		t.Error("a missing directory should be an error, so a typo in AUDIT_DIR is noticed")
	}
}

// ---- found by review ----

// A collector that accepts the connection and never answers must cost the
// run one timeout, not one per event.
func TestAHungCollectorCostsOneTimeoutNotOnePerEvent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }() // never speaks TLS; holds the connection open
		}
	}()
	dir := t.TempDir()
	l, warn := logger(dir)
	l.Forward = &Forwarder{Addr: ln.Addr().String(), Proto: "tls", Timeout: 400 * time.Millisecond}
	start := time.Now()
	for i := 0; i < 10; i++ {
		_ = l.Emit(Event{Action: "a", Outcome: Success})
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("10 events took %v: the dead collector was dialled for each", took)
	}
	if strings.Count(warn.String(), "forwarding is off for the rest of this run") != 1 {
		t.Errorf("want one warning saying forwarding is off, got %q", warn.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "audit-2026-11-19.log"))
	if strings.Count(string(b), "\n") != 10 {
		t.Errorf("the local file lost events: %q", b)
	}
}

func TestAFIFOWhereTheDaysFileGoesCannotHangTheLane(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "audit-2026-11-19.log"), 0o600); err != nil {
		t.Skip("no fifos here")
	}
	l, warn := logger(dir)
	done := make(chan error, 1)
	go func() { done <- l.Emit(Event{Action: "a", Outcome: Success}) }()
	select {
	case err := <-done:
		// With no reader the open itself fails (ENXIO); with one it would be
		// refused as not a regular file. Either way: an error, the event on
		// stderr, and no hang.
		if err == nil || !strings.Contains(warn.String(), "cannot write") || !strings.Contains(warn.String(), "<86>1 ") {
			t.Fatalf("a FIFO was accepted: %v %q", err, warn.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Emit hung on a FIFO")
	}
}

func TestARelativeAuditDirIsRefused(t *testing.T) {
	l, warn := logger("relative/dir")
	if err := l.Emit(Event{Action: "a", Outcome: Success}); err == nil {
		t.Fatal("a relative AUDIT_DIR was used")
	}
	if !strings.Contains(warn.String(), "not an absolute path") {
		t.Errorf("warning: %q", warn.String())
	}
	if _, err := os.Stat("relative"); err == nil {
		t.Error("a directory was created from the working directory")
	}
}

func TestLineAndParagraphSeparatorsAreNeutralised(t *testing.T) {
	l, _ := logger(t.TempDir())
	line := l.Format(fixed, Event{Action: "a", Target: "x y z", Outcome: Success, Detail: "d e"})
	if strings.ContainsAny(line, "  ") {
		t.Fatalf("a separator survived: %q", line)
	}
}

func TestALongRecipientListSurvivesInTheTarget(t *testing.T) {
	l, _ := logger(t.TempDir())
	var addrs []string
	for i := 0; i < 30; i++ {
		addrs = append(addrs, fmt.Sprintf("person%02d@example.com", i))
	}
	line := l.Format(fixed, Event{Action: "mail.send", Target: strings.Join(addrs, ","), Outcome: Success})
	for _, a := range addrs {
		if !strings.Contains(line, a) {
			t.Fatalf("recipient %s was cut off: %s", a, line)
		}
	}
}
