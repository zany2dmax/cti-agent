// fleet-trace keeps and reads a record of what each heartbeat did, and what
// each model call in the fleet cost.
//
//	fleet-trace init
//	fleet-trace tee --out FILE --plain FILE [--max-mb N] [--keep minimal|full]
//	fleet-trace unwrap --result FILE [--trace FILE]
//	fleet-trace show [FILE | --last] [--full]
//	fleet-trace list [-n N]
//	fleet-trace prune --days N
//
// Traces live in $FLEET_HOME/state/traces, 0600 in a 0700 directory.
//
// What a trace keeps (--keep, CHECKIN_TRACE_KEEP in run-checkin). By default
// MINIMAL, and by ALLOWLIST: what the model wrote, every tool call and its
// arguments, what was denied, the turns, tokens, cost and the final result.
// A tool result (a mail body, an advisory, a report) is replaced by its size
// and the first 16 characters of its SHA-256, so "what did it look at" is
// answerable and the trace is not a second copy of the mailbox. So is
// anything in an event shape this program does not know. FULL keeps every
// event as it came, for an investigation; untrusted text then sits in the
// trace, which is handled like a report and deleted after CHECKIN_TRACE_DAYS.
//
// --plain gets exactly what the CLI's text mode printed (stderr lines, API
// error messages, the result text), because cti-budget classifies a hold by
// words such as "429" and "billing" in it, and token counts or tool output
// there would read as one.
//
// unwrap is for the lanes that call Claude with --output-format json
// (run-supplier): it hands the lane the answer text mode gave, and keeps the
// cost in a supplier-<timestamp>.jsonl trace - usage and cost only.
//
// tee never stops reading stdin: if it exited early, claude would die of
// SIGPIPE in the middle of a beat; a failure to write the trace stops the
// trace, not the reading.
//
// It replaced the Python fleet-trace, file for file: the same trace lines
// byte for byte (internal/pyjson writes them as Python's json.dumps did),
// the same timeline, plain text, list and messages. The Go tests hold it to
// golden output that Python wrote.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zany2dmax/cti-agent/internal/pyfmt"
	"github.com/zany2dmax/cti-agent/internal/pyjson"
)

const usageText = `  fleet-trace init                    create the trace directory (0700)
  fleet-trace tee --out FILE --plain FILE [--max-mb N] [--keep minimal|full]
                                      read a beat's stream-json on stdin: keep
                                      its events in --out (by default without
                                      the content the beat read; --keep full
                                      keeps everything), print a timeline for
                                      the journal, write the beat's plain text
                                      (what cti-budget classifies) to --plain
  fleet-trace unwrap --result FILE [--trace FILE]
                                      read one ` + "`claude -p --output-format json`" + `
                                      reply on stdin: write the model's answer
                                      to --result, and add what the call cost
                                      (never its text) to --trace
  fleet-trace show [FILE | --last] [--full]
                                      print one beat as a timeline
  fleet-trace list [-n N]             the latest traces, one line each, with
                                      what they cost and a total
  fleet-trace prune --days N          delete traces older than N days`

// checkin- is a heartbeat; supplier- is one run of the supplier lane.
var traceName = regexp.MustCompile(`^(checkin|supplier)-(\d{8}T\d{6})(-\d+)?\.jsonl$`)

var units = []string{"checkin", "supplier"}

// exit is how a subcommand ends: a status, after its output.
type exit int

type app struct {
	traceDir       string
	stdin          io.Reader
	stdout, stderr io.Writer
	now            func() time.Time
}

func main() {
	home := os.Getenv("FLEET_HOME")
	if home == "" {
		h, _ := os.UserHomeDir()
		home = filepath.Join(h, "fleet")
	}
	syscall.Umask(0o077)
	out := bufio.NewWriter(os.Stdout)
	a := &app{traceDir: filepath.Join(home, "state", "traces"), stdin: os.Stdin, stdout: out, stderr: os.Stderr, now: time.Now}
	code := a.run(os.Args[1:])
	_ = out.Flush()
	os.Exit(code)
}

func (a *app) run(argv []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(exit)
			if !ok {
				panic(r)
			}
			code = int(e)
		}
	}()
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		a.usage("")
	}
	sub, args := argv[0], argv[1:]
	cmds := map[string]func([]string){"init": a.cmdInit, "tee": a.cmdTee, "unwrap": a.cmdUnwrap,
		"show": a.cmdShow, "list": a.cmdList, "prune": a.cmdPrune}
	cmd, ok := cmds[sub]
	if !ok {
		a.usage("unknown subcommand " + pyfmt.ReprString(sub))
	}
	cmd(args)
	return 0
}

func (a *app) usage(msg string) {
	if msg != "" {
		_, _ = fmt.Fprintf(a.stderr, "fleet-trace: %s\n", msg)
	}
	_, _ = fmt.Fprintf(a.stderr, "usage:\n%s\n", usageText)
	panic(exit(2))
}

func (a *app) fail(format string, args ...any) {
	_, _ = fmt.Fprintf(a.stderr, "fleet-trace: "+format+"\n", args...)
	panic(exit(1))
}

// strerror is the C library's message for an error, as Python printed it.
func strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		s := errno.Error()
		if s != "" {
			return strings.ToUpper(s[:1]) + s[1:]
		}
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return strerror(pe.Err)
	}
	return err.Error()
}

func parse(raw string) obj {
	v, err := pyjson.Decode([]byte(raw))
	if err != nil {
		return nil
	}
	o, _ := v.(obj)
	return o
}

func header(unit, keep string, now time.Time) string {
	o := pyjson.NewObject()
	o.Set("type", "fleet_trace")
	o.Set("version", jsonNumber("1"))
	o.Set("unit", unit)
	if keep != "" {
		o.Set("keep", keep)
	}
	o.Set("started", now.Format("2006-01-02T15:04:05-0700"))
	return pyjson.Dumps(o, pyjson.Options{EnsureASCII: true})
}

func (a *app) cmdInit(args []string) {
	if len(args) > 0 {
		a.usage("init takes no arguments")
	}
	if err := os.MkdirAll(a.traceDir, 0o700); err != nil {
		a.fail("cannot create %s: %s", a.traceDir, strerror(err))
	}
	if st, err := os.Lstat(a.traceDir); err != nil || !st.IsDir() {
		a.fail("%s is not a directory", a.traceDir)
	}
	// #nosec G302 -- a directory: 0700 is owner-only, and it needs x to be entered.
	if err := os.Chmod(a.traceDir, 0o700); err != nil {
		a.fail("cannot set the mode of %s: %s", a.traceDir, strerror(err))
	}
	// A real write, so a full or read-only disk turns traces off before the
	// beat rather than during it.
	probe := filepath.Join(a.traceDir, fmt.Sprintf(".probe-%d", os.Getpid()))
	// #nosec G304 -- a fixed name in the trace directory.
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_, err = f.WriteString("ok\n")
		_ = f.Close()
	}
	if err != nil {
		a.fail("cannot write in %s: %s", a.traceDir, strerror(err))
	}
	_ = os.Remove(probe)
	_, _ = fmt.Fprintln(a.stdout, a.traceDir)
}

// openNew creates path 0600, never through a link or onto a file that is
// already there.
func openNew(path string) (*os.File, error) {
	// #nosec G304,G703 -- the runner's own trace or result path: created
	// new (O_EXCL), never through a link (O_NOFOLLOW).
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

func (a *app) cmdTee(args []string) {
	var outPath, plainPath string
	haveOut, havePlain := false, false
	maxMB := 20
	keepMode := "minimal"
	next := func(i *int) (string, bool) {
		*i++
		if *i < len(args) {
			return args[*i], true
		}
		return "", false
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			outPath, haveOut = next(&i)
		case "--plain":
			plainPath, havePlain = next(&i)
		case "--max-mb":
			v, _ := next(&i)
			n, err := strconv.Atoi(v)
			if !asciiDigits(v) || err != nil || n < 1 {
				a.usage("--max-mb takes a whole number of megabytes, 1 or more")
			}
			maxMB = n
		case "--keep":
			keepMode, _ = next(&i)
			if keepMode != "minimal" && keepMode != "full" {
				a.usage("--keep takes minimal or full")
			}
		default:
			a.usage("unknown argument " + pyfmt.ReprString(args[i]))
		}
	}
	if !haveOut || !havePlain || outPath == "" || plainPath == "" {
		a.usage("tee needs --out FILE and --plain FILE")
	}
	maxBytes := maxMB * 1024 * 1024

	var errs []string
	trace, err := openNew(outPath)
	if err != nil {
		trace = nil
		errs = append(errs, fmt.Sprintf("cannot create %s: %s", outPath, strerror(err)))
	}
	// --plain is run-checkin's mktemp file: it exists already, 0600.
	// #nosec G304 -- the runner's own temporary file.
	plain, err := os.OpenFile(plainPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		plain = nil
		errs = append(errs, fmt.Sprintf("cannot write %s: %s", plainPath, strerror(err)))
	}
	written := 0
	keep := func(line string) {
		if trace == nil {
			return
		}
		data := line + "\n"
		if written+len(data) > maxBytes {
			o := pyjson.NewObject()
			o.Set("type", "fleet_trace")
			o.Set("truncated", true)
			o.Set("max_bytes", jsonNumber(strconv.Itoa(maxBytes)))
			_, _ = trace.WriteString(pyjson.Dumps(o, pyjson.Options{EnsureASCII: true}) + "\n")
			_ = trace.Close()
			trace = nil
			errs = append(errs, fmt.Sprintf("trace stopped at %d MB (--max-mb)", maxMB))
			return
		}
		if _, err := trace.WriteString(data); err != nil {
			errs = append(errs, fmt.Sprintf("trace write failed: %s; trace stopped", strerror(err)))
			_ = trace.Close()
			trace = nil
			return
		}
		written += len(data)
	}
	keep(header("checkin", keepMode, a.now()))
	tl := newTimeline(a.stdout, false)
	r := bufio.NewReaderSize(a.stdin, 1<<20)
	for {
		rawb, readErr := r.ReadBytes('\n')
		if len(rawb) > 0 {
			raw := strings.TrimRight(pyjson.DecodeBytes(rawb), "\r\n")
			if exc := a.teeLine(raw, keepMode, keep, tl, plain); exc != "" {
				errs = append(errs, "line skipped: "+exc)
			}
		}
		if readErr != nil {
			break
		}
	}
	if trace != nil {
		_ = trace.Close()
	}
	if plain != nil {
		_ = plain.Close()
	}
	seen := map[string]bool{}
	for _, e := range errs {
		if !seen[e] {
			seen[e] = true
			_, _ = fmt.Fprintf(a.stderr, "fleet-trace: %s\n", e)
		}
	}
	if _, err := os.Stat(outPath); err == nil {
		_, _ = fmt.Fprintf(a.stdout, "[trace] kept in %s\n", outPath)
	}
	if len(errs) > 0 {
		panic(exit(1))
	}
}

// teeLine handles one line of the stream. A malformed event raises as it
// did in Python, and the reading goes on: the name comes back for the
// "line skipped" message.
func (a *app) teeLine(raw, keepMode string, keep func(string), tl *timeline, plain io.Writer) (exc string) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(pyExc)
			if !ok {
				exc = "Exception"
				return
			}
			exc = string(e)
		}
	}()
	if pyStrip(raw) == "" {
		return ""
	}
	ev := parse(raw)
	switch {
	case ev == nil:
		// Not JSON: stderr or a crash message. Capped in the default trace,
		// since it can echo what the beat was reading.
		text := raw
		if keepMode != "full" {
			text = clean(raw, 2000, false)
		}
		o := pyjson.NewObject()
		o.Set("type", "fleet_trace_text")
		o.Set("text", text)
		keep(pyjson.Dumps(o, pyjson.Options{}))
	case keepMode == "full":
		keep(raw)
	default:
		keep(pyjson.Dumps(minimize(ev), pyjson.Options{}))
	}
	if ev == nil {
		_, _ = fmt.Fprintln(a.stdout, raw)
	} else {
		tl.event(ev)
	}
	if plain != nil {
		for _, l := range plainLines(ev, raw) {
			_, _ = io.WriteString(plain, l+"\n")
		}
	}
	if f, ok := a.stdout.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
	return ""
}

func asciiDigits(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type traceFile struct{ stamp, suffix, name, path string }

// traces is every trace, oldest first by the time in its name (not by name,
// which would put every heartbeat before every supplier run).
func (a *app) traces(unit string) []string {
	entries, err := os.ReadDir(a.traceDir)
	if err != nil {
		return nil
	}
	var out []traceFile
	for _, e := range entries {
		m := traceName.FindStringSubmatch(e.Name())
		p := filepath.Join(a.traceDir, e.Name())
		if m == nil || (unit != "" && m[1] != unit) {
			continue
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		out = append(out, traceFile{m[2], m[3], e.Name(), p})
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.stamp != y.stamp {
			return x.stamp < y.stamp
		}
		if x.suffix != y.suffix {
			return x.suffix < y.suffix
		}
		return x.name < y.name
	})
	paths := make([]string, len(out))
	for i, t := range out {
		paths[i] = t.path
	}
	return paths
}

// readLines is a file as Python's text mode read it: invalid bytes
// replaced, \r\n and \r taken as line ends.
func readLines(path string) ([]string, error) {
	// #nosec G304,G703 -- a trace the operator named on show's command line,
	// read only: the operator can read it anyway.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(pyjson.DecodeBytes(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}

func (a *app) cmdShow(args []string) {
	full := false
	var rest []string
	for _, x := range args {
		if x == "--full" {
			full = true
		} else {
			rest = append(rest, x)
		}
	}
	var path string
	switch {
	case len(rest) == 0 || (len(rest) == 1 && rest[0] == "--last"):
		// The newest heartbeat: a supplier run every morning must not hide
		// the beat an operator is looking for.
		traces := a.traces("checkin")
		if len(traces) == 0 {
			a.fail("no traces in %s", a.traceDir)
		}
		path = traces[len(traces)-1]
	case len(rest) == 1 && !strings.HasPrefix(rest[0], "-"):
		path = rest[0]
		if !strings.Contains(path, "/") {
			path = filepath.Join(a.traceDir, path)
		}
	default:
		a.usage("show takes one FILE, or --last, and optionally --full")
	}
	_, _ = fmt.Fprintf(a.stdout, "== %s\n", path)
	lines, err := readLines(path)
	if err != nil {
		a.fail("cannot read %s: %s", path, strerror(err))
	}
	tl := newTimeline(a.stdout, full)
	for i, raw := range lines {
		ev := parse(raw)
		if ev == nil {
			continue
		}
		if exc := showEvent(tl, ev); exc != "" {
			// Python stopped here with a traceback; stop at the same place,
			// with a message instead.
			a.fail("cannot read %s: line %d is not an event this program can show (%s)", path, i+1, exc)
		}
	}
}

func showEvent(tl *timeline, ev obj) (exc string) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(pyExc)
			if !ok {
				panic(r)
			}
			exc = string(e)
		}
	}()
	tl.event(ev)
	return ""
}

type summary struct {
	isError bool
	turns   string
	denied  int
	cost    *float64
	calls   int
}

// summarize is what one trace adds up to, read from the end of the file: a
// heartbeat has one result event, a supplier run one per request it judged.
func summarize(path string) (int64, *summary) {
	// #nosec G304 -- a trace in the trace directory.
	f, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return 0, nil
	}
	size := st.Size()
	start := size - 256*1024
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return size, nil
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return size, nil
	}
	var results []obj
	for _, line := range pySplitLines(pyjson.DecodeBytes(raw)) {
		if ev := parse(line); ev != nil && ev.Get("type") == "result" {
			results = append(results, ev)
		}
	}
	if len(results) == 0 {
		return size, nil
	}
	s := &summary{calls: len(results)}
	var costs []float64
	turns, haveTurns := 0.0, false
	for _, ev := range results {
		if truthy(ev.Get("is_error")) {
			s.isError = true
		}
		if c := ev.Get("total_cost_usd"); isNumber(c) {
			v := num(c)
			if !math.IsInf(v, 0) && !math.IsNaN(v) {
				costs = append(costs, v)
			}
		}
		if t := ev.Get("num_turns"); isInt(t) {
			turns += num(t)
			haveTurns = true
		}
		if d, ok := ev.Get("permission_denials").([]any); ok {
			s.denied += len(d)
		}
	}
	s.turns = "-"
	if haveTurns {
		s.turns = strconv.FormatFloat(turns, 'f', -1, 64)
	}
	if len(costs) > 0 {
		total := 0.0
		for _, c := range costs {
			total += c
		}
		s.cost = &total
	}
	return size, s
}

// pySplitLines is str.splitlines(), every separator Python knows.
func pySplitLines(s string) []string {
	var out []string
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case '\r':
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			fallthrough
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func money(v float64) string { return "$" + strconv.FormatFloat(v, 'f', 4, 64) }

func (a *app) cmdList(args []string) {
	n := 10
	if len(args) > 0 {
		if len(args) != 2 || args[0] != "-n" || !asciiDigits(args[1]) {
			a.usage("list takes -n N")
		}
		n, _ = strconv.Atoi(args[1])
	}
	traces := a.traces("")
	if n > 0 && len(traces) > n {
		traces = traces[len(traces)-n:]
	}
	if len(traces) == 0 {
		_, _ = fmt.Fprintf(a.stdout, "(no traces in %s)\n", a.traceDir)
		return
	}
	_, _ = fmt.Fprintf(a.stdout, "%-34s %8s  %-6s %5s %5s %6s %9s\n", "trace", "size", "result", "calls", "turns", "denied", "cost")
	totals := map[string]float64{}
	var order []string
	for i := len(traces) - 1; i >= 0; i-- {
		p := traces[i]
		base := filepath.Base(p)
		size, s := summarize(p)
		if s == nil {
			_, _ = fmt.Fprintf(a.stdout, "%-34s %8d  %-6s %5s %5s %6s %9s\n", base, size, "none", "-", "-", "-", "-")
			continue
		}
		cost := "-"
		if s.cost != nil {
			unit := traceName.FindStringSubmatch(base)[1]
			if _, ok := totals[unit]; !ok {
				order = append(order, unit)
			}
			totals[unit] += *s.cost
			cost = money(*s.cost)
		}
		result := "ok"
		if s.isError {
			result = "ERROR"
		}
		_, _ = fmt.Fprintf(a.stdout, "%-34s %8d  %-6s %5d %5s %6d %9s\n", base, size, result, s.calls, s.turns, s.denied, cost)
	}
	if len(totals) > 0 {
		var parts []string
		for _, u := range units {
			if v, ok := totals[u]; ok {
				parts = append(parts, u+" "+money(v))
			}
		}
		sum := 0.0
		for _, u := range order {
			sum += totals[u]
		}
		_, _ = fmt.Fprintf(a.stdout, "total for the %d listed: %s (%s)\n", len(traces), money(sum), strings.Join(parts, ", "))
	}
}

func (a *app) cmdPrune(args []string) {
	if len(args) != 2 || args[0] != "--days" || !asciiDigits(args[1]) {
		a.usage("prune takes --days N")
	}
	days, _ := strconv.Atoi(args[1])
	cutoff := a.now().Add(-time.Duration(days) * 24 * time.Hour)
	removed := 0
	for _, p := range a.traces("") {
		st, err := os.Lstat(p)
		if err == nil && st.ModTime().Before(cutoff) {
			if os.Remove(p) == nil {
				removed++
			}
		}
	}
	_, _ = fmt.Fprintf(a.stdout, "fleet-trace: pruned %d trace(s) older than %d days\n", removed, days)
}

var (
	usageKeys  = []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"}
	resultKeys = []string{"subtype", "is_error", "num_turns", "duration_ms", "total_cost_usd"}
)

// costOnly is what unwrap keeps of a reply: the numbers, never the text.
func costOnly(ev obj) obj {
	out := pyjson.NewObject()
	out.Set("type", "result")
	for _, k := range resultKeys {
		v := ev.Get(k)
		_, isBool := v.(bool)
		_, isStr := v.(string)
		if isBool || isNumber(v) || (k == "subtype" && isStr) {
			if k == "subtype" {
				out.Set(k, clean(v, 40, true))
			} else {
				out.Set(k, v)
			}
		}
	}
	if u, ok := ev.Get("usage").(obj); ok {
		kept := pyjson.NewObject()
		for _, k := range usageKeys {
			if isInt(u.Get(k)) {
				kept.Set(k, u.Get(k))
			}
		}
		out.Set("usage", kept)
	}
	if models, ok := ev.Get("modelUsage").(obj); ok {
		names := make([]string, 0, models.Len())
		for _, m := range models.Keys {
			names = append(names, clean(m, 80, true))
		}
		sort.Strings(names)
		if len(names) > 5 {
			names = names[:5]
		}
		l := make([]any, len(names))
		for i, s := range names {
			l[i] = s
		}
		out.Set("models", l)
	}
	return out
}

// appendTrace adds one line to a trace: created 0600 with its header the
// first time, appended after that, never through a link (and a FIFO planted
// at the path must not hang the lane).
func (a *app) appendTrace(path string, ev obj, unit string) error {
	flags := syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	first := true
	// #nosec G304,G703 -- the lane's own trace path, its name checked
	// against supplier-<timestamp>.jsonl; no link is followed.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|flags, 0o600)
	if errors.Is(err, os.ErrExist) {
		first = false
		// #nosec G304,G703 -- as above.
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|flags, 0)
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	var b bytes.Buffer
	if first {
		b.WriteString(header(unit, "", a.now()) + "\n")
	}
	b.WriteString(pyjson.Dumps(ev, pyjson.Options{EnsureASCII: true}) + "\n")
	_, err = f.Write(b.Bytes())
	return err
}

func (a *app) cmdUnwrap(args []string) {
	var resultPath, tracePath string
	haveResult, haveTrace := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--result":
			if i+1 < len(args) {
				resultPath, haveResult = args[i+1], true
			}
			i++
		case "--trace":
			if i+1 < len(args) {
				tracePath, haveTrace = args[i+1], true
			}
			i++
		default:
			a.usage("unknown argument " + pyfmt.ReprString(args[i]))
		}
	}
	if !haveResult || resultPath == "" {
		a.usage("unwrap needs --result FILE")
	}
	if haveTrace {
		m := traceName.FindStringSubmatch(filepath.Base(tracePath))
		if m == nil || m[1] == "checkin" {
			a.usage("--trace must be named supplier-<YYYYMMDDTHHMMSS>.jsonl")
		}
	}
	raw, _ := io.ReadAll(io.LimitReader(a.stdin, 16*1024*1024))
	ev := parse(pyStrip(pyjson.DecodeBytes(raw)))
	if ev == nil || ev.Get("type") != "result" {
		a.fail("the reply is not a claude JSON result")
	}
	// The cost is kept even when the answer is unusable: a failed call is
	// still billed. A trace that cannot be written costs the record, not the
	// judgement.
	if haveTrace {
		if err := a.appendTrace(tracePath, costOnly(ev), "supplier"); err != nil {
			_, _ = fmt.Fprintf(a.stderr, "fleet-trace: cost not recorded in %s: %s\n", tracePath, strerror(err))
		}
	}
	answer, ok := ev.Get("result").(string)
	if truthy(ev.Get("is_error")) || !ok || pyStrip(answer) == "" {
		a.fail("the model returned no usable answer (%s)", clean(or(ev.Get("subtype"), "no answer"), 80, true))
	}
	f, err := openNew(resultPath)
	if err != nil {
		a.fail("cannot write %s: %s", resultPath, strerror(err))
	}
	if _, err := f.WriteString(answer); err != nil {
		_ = f.Close()
		a.fail("cannot write %s: %s", resultPath, strerror(err))
	}
	_ = f.Close()
}
