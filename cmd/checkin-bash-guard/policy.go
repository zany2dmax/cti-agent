package main

// The argument policy (PrimeSec design review 39260, Scenario-223) and the
// per-beat limits (Scenario-224). tests/test_lanes.py fails when a command
// in run-checkin's grant has no row here.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

var handles = set("@all", "@operator", "@you", "@ingest", "@enrich", "@scout", "@brief",
	"@patchtuesday", "@mailbox", "@appscan", "@appowners", "@domains", "@vmscan", "@supplier")

var boardKinds = set("INFO", "Q", "A", "APPROVE", "P1", "ERROR")

const (
	maxBoardMessage = 400
	maxMemory       = 1500
	maxReason       = 800 // cti-alert itself cuts a reason at 600
)

var (
	idRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}\z`)
	numIDRE    = regexp.MustCompile(`^[0-9]{1,9}\z`)
	unitGlobRE = regexp.MustCompile(`^cti-agent-[A-Za-z0-9@._*-]{1,60}\z`)
	printable  = regexp.MustCompile(`^[\x20-\x7e]*\z`)
	sinceRE    = regexp.MustCompile(`^[A-Za-z0-9 :.+-]+\z`)
)

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range items {
		m[s] = true
	}
	return m
}

// short is what a refusal quotes of a value: at most 40 characters, escaped.
func short(s string) string {
	if utf8.RuneCountInString(s) > 40 {
		s = string([]rune(s)[:40]) + "..."
	}
	return repr(s)
}

type check func(string) string

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

func intIn(lo, hi int) check {
	return func(v string) string {
		if !asciiDigits(v) || len(v) > 9 {
			return "is not a number"
		}
		n, _ := strconv.Atoi(v)
		if n < lo || n > hi {
			return fmt.Sprintf("must be %d to %d", lo, hi)
		}
		return ""
	}
}

func rx(pattern, what string) check {
	re := regexp.MustCompile(`^` + pattern + `\z`)
	return func(v string) string {
		if re.MatchString(v) {
			return ""
		}
		return "is not " + what
	}
}

func oneOf(allowed ...string) check {
	return func(v string) string {
		for _, a := range allowed {
			if v == a {
				return ""
			}
		}
		return "must be one of " + strings.Join(allowed, " ")
	}
}

// pySpace is Python's str.isspace, which strip() removes.
func pySpace(r rune) bool {
	switch {
	case r >= 0x1c && r <= 0x1f, r == 0x85, r == 0xa0:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r) || r == 0x2028 || r == 0x2029
}

func text(limit int) check {
	return func(v string) string {
		if strings.TrimFunc(v, pySpace) == "" {
			return "is empty"
		}
		if n := utf8.RuneCountInString(v); n > limit {
			return fmt.Sprintf("is too long (%d characters, at most %d)", n, limit)
		}
		if !printable.MatchString(v) {
			return "has characters other than plain printable ASCII"
		}
		return ""
	}
}

// flags checks `--flag [value]` arguments against spec (a nil check is a
// flag with no value). No positional arguments and no --flag=value form:
// both are places a value hides from the rules.
func flags(args []string, spec map[string]check, valueless ...string) string {
	none := set(valueless...)
	seen := map[string]bool{}
	for i := 0; i < len(args); {
		a := args[i]
		c, ok := spec[a]
		if !ok && !none[a] {
			return short(a) + " is not an allowed argument here"
		}
		if seen[a] {
			return a + " is given twice"
		}
		seen[a] = true
		if none[a] {
			i++
			continue
		}
		if i+1 >= len(args) {
			return a + " needs a value"
		}
		if bad := c(args[i+1]); bad != "" {
			return a + " " + bad
		}
		i += 2
	}
	return ""
}

func takesNone(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return "takes no arguments (got " + short(args[0]) + ")"
}

func polBoard(a []string) string {
	if len(a) == 0 {
		return "needs a subcommand"
	}
	sub, rest := a[0], a[1:]
	switch sub {
	case "say":
		if len(rest) < 3 {
			return "say takes @handle KIND and a message"
		}
		if !handles[rest[0]] {
			return short(rest[0]) + " is not a handle the beat may post to"
		}
		if !boardKinds[rest[1]] {
			kinds := make([]string, 0, len(boardKinds))
			for k := range boardKinds {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			return "the kind must be one of " + strings.Join(kinds, " ")
		}
		if bad := text(maxBoardMessage)(strings.Join(rest[2:], " ")); bad != "" {
			return "the message " + bad
		}
		return ""
	case "read":
		if len(rest) > 1 {
			return "read takes at most one handle"
		}
		if len(rest) == 1 && !handles[rest[0]] {
			return short(rest[0]) + " is not a handle"
		}
		return ""
	case "tail":
		// `tail -n 8` is how a model writes it; fleet-board takes both forms.
		if len(rest) > 0 && rest[0] == "-n" {
			rest = rest[1:]
			if len(rest) == 0 {
				return "tail -n needs a number"
			}
		}
		if len(rest) > 1 {
			return "tail takes at most one number"
		}
		if len(rest) == 1 {
			if bad := intIn(1, 200)(rest[0]); bad != "" {
				return "the line count " + bad
			}
		}
		return ""
	case "resolve":
		if len(rest) != 1 || !idRE.MatchString(rest[0]) {
			return "resolve takes one board id"
		}
		return ""
	case "expire":
		if len(rest) != 1 {
			return "expire takes one number of days"
		}
		if bad := intIn(2, 365)(rest[0]); bad != "" {
			return "the days " + bad
		}
		return ""
	}
	return "fleet-board " + short(sub) + " is not granted"
}

var (
	cveRE      = `CVE-[0-9]{4}-[0-9]{4,7}`
	dateRE     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}(-[0-9]{2})?\z`)
	kindRE     = regexp.MustCompile(`^[a-z]{1,20}\z`)
	categoryRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}\z`)
	topicRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\z`)
)

func polDB(a []string) string {
	if len(a) == 0 {
		return "needs a subcommand"
	}
	sub, rest := a[0], a[1:]
	switch sub {
	case "recent":
		if len(rest) > 1 {
			return "recent takes at most one number"
		}
		if len(rest) == 1 {
			if bad := intIn(1, 100)(rest[0]); bad != "" {
				return "the count " + bad
			}
		}
		return ""
	case "findings":
		return flags(rest, map[string]check{
			"--cve":        rx(cveRE, "a CVE id"),
			"--priority":   rx(`Sev[1-5]`, "Sev1 to Sev5"),
			"--stale-days": intIn(1, 3650),
			"--status":     rx(`[A-Z_]{1,20}`, "a status word")})
	case "was-sent":
		if len(rest) != 2 {
			return "was-sent takes a date and a kind"
		}
		if !dateRE.MatchString(rest[0]) {
			return short(rest[0]) + " is not a date or month"
		}
		if !kindRE.MatchString(rest[1]) {
			return short(rest[1]) + " is not a digest kind"
		}
		return ""
	case "rollup":
		return flags(rest, map[string]check{"--days": intIn(1, 90)})
	case "remember":
		if len(rest) != 3 {
			return "remember takes a category, a topic and the text"
		}
		if !categoryRE.MatchString(rest[0]) {
			return short(rest[0]) + " is not a category"
		}
		if !topicRE.MatchString(rest[1]) {
			return short(rest[1]) + " is not a topic"
		}
		if bad := text(maxMemory)(rest[2]); bad != "" {
			return "the text " + bad
		}
		return ""
	case "task":
		switch {
		case len(rest) == 1 && rest[0] == "list":
			return ""
		case len(rest) == 2 && rest[0] == "add":
			if bad := text(200)(rest[1]); bad != "" {
				return "the title " + bad
			}
			return ""
		case len(rest) == 2 && rest[0] == "done" && numIDRE.MatchString(rest[1]):
			return ""
		}
		return "task takes: list, add TITLE, or done ID"
	case "ack":
		if len(rest) == 1 && numIDRE.MatchString(rest[0]) {
			return ""
		}
		return "ack takes one number"
	case "mail":
		switch {
		case len(rest) == 2 && rest[0] == "ack" && numIDRE.MatchString(rest[1]):
			return ""
		case len(rest) == 2 && rest[0] == "inbox" && idRE.MatchString(rest[1]):
			return ""
		case len(rest) == 4 && rest[0] == "send" && idRE.MatchString(rest[1]) && idRE.MatchString(rest[2]):
			if bad := text(maxBoardMessage)(rest[3]); bad != "" {
				return "the body " + bad
			}
			return ""
		}
		return "mail takes: ack ID, inbox AGENT, or send AGENT KIND BODY"
	case "vacuum":
		return takesNone(rest)
	}
	return "fleet-db " + short(sub) + " is not granted"
}

func polAlert(a []string) string {
	if bad := flags(a, map[string]check{
		"--unit":   oneOf("cti-agent-checkin.service"),
		"--kind":   oneOf("ESCALATION"),
		"--reason": text(maxReason)}, "--for-real", "--dry-run"); bad != "" {
		return bad
	}
	if contains(a, "--for-real") == contains(a, "--dry-run") {
		return "give exactly one of --for-real and --dry-run"
	}
	for _, need := range []string{"--unit", "--kind", "--reason"} {
		if !contains(a, need) {
			return need + " is required"
		}
	}
	return ""
}

func polKEV(a []string) string {
	return flags(a, map[string]check{"--horizon": intIn(1, 365)}, "--hosts", "--json", "--quiet", "--fail-if-overdue")
}

func exactly(want ...string) func([]string) string {
	return func(a []string) string {
		if len(a) == len(want) {
			same := true
			for i := range a {
				if a[i] != want[i] {
					same = false
				}
			}
			if same {
				return ""
			}
		}
		return "only `" + strings.Join(want, " ") + "` is granted"
	}
}

func polPatchTuesday(a []string) string {
	if len(a) == 0 || a[0] != "--dry-run" {
		return "must start with --dry-run"
	}
	return flags(a[1:], map[string]check{
		"--month":    rx(`[0-9]{4}-(0[1-9]|1[0-2])`, "YYYY-MM"),
		"--max-rows": intIn(0, 1000)}, "--subject-only")
}

func polJournal(a []string) string {
	units := 0
	for i := 0; i < len(a); {
		flag := a[i]
		if flag == "--no-pager" {
			i++
			continue
		}
		if i+1 >= len(a) {
			return short(flag) + " needs a value"
		}
		v := a[i+1]
		switch flag {
		case "-u", "--unit":
			if !unitGlobRE.MatchString(v) {
				return "unit " + short(v) + " is not one of the fleet's (cti-agent-...)"
			}
			units++
		case "--since":
			if utf8.RuneCountInString(v) > 40 || !sinceRE.MatchString(v) {
				return "--since " + short(v) + " is not a time"
			}
		case "-n", "--lines":
			if bad := intIn(1, 5000)(v); bad != "" {
				return flag + " " + bad
			}
		default:
			return short(flag) + " is not an allowed argument here"
		}
		i += 2
	}
	if units == 0 {
		return "at least one -u cti-agent-... is required"
	}
	return ""
}

func polTimers(a []string) string {
	for _, v := range a {
		if v != "--all" && v != "-a" && !unitGlobRE.MatchString(v) {
			return "argument " + short(v) + " is not --all or a cti-agent pattern"
		}
	}
	return ""
}

var policy = map[string]func([]string) string{
	"fleet-board":      polBoard,
	"fleet-db":         polDB,
	"cti-alert":        polAlert,
	"cti-kev":          polKEV,
	"cti-budget":       exactly("status"),
	"cti-patchtuesday": polPatchTuesday,
	"cti-mailbox":      exactly("--dry-run"),
	"fleet-journal":    polJournal,
	"fleet-timers":     polTimers,
	// Not the credential checks (cti-mailer --check and each lane's): they
	// run in cti-agent-credcheck, and the beat reads reports/credcheck.txt.
}

// ── per-beat limits (Scenario-224) ─────────────────────────────────────────

var defaultLimits = map[string]int{"bash": 20, "alert": 2, "board_write": 4, "db_write": 6}

var limitEnv = map[string]string{"bash": "CHECKIN_MAX_BASH", "alert": "CHECKIN_MAX_ALERTS",
	"board_write": "CHECKIN_MAX_BOARD_WRITES", "db_write": "CHECKIN_MAX_DB_WRITES"}

var beatIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}\z`)

func (g guard) limit(kind string) int {
	v := g.getenv(limitEnv[kind])
	if asciiDigits(v) {
		if n, _ := strconv.Atoi(v); n > 0 && n <= 1000 {
			return n
		}
	}
	return defaultLimits[kind]
}

// pyError names an error as the counter's refusal always has.
func pyError(err error) string {
	var se *json.SyntaxError
	switch {
	case errors.As(err, &se), errors.Is(err, errJSON):
		return "JSONDecodeError"
	case errors.Is(err, errValue):
		return "ValueError"
	case errors.Is(err, errUnicode):
		return "UnicodeDecodeError"
	case errors.Is(err, fs.ErrNotExist):
		return "FileNotFoundError"
	case errors.Is(err, fs.ErrPermission):
		return "PermissionError"
	case errors.Is(err, fs.ErrExist):
		return "FileExistsError"
	case errors.Is(err, syscall.ENOTDIR):
		return "NotADirectoryError"
	case errors.Is(err, syscall.EISDIR):
		return "IsADirectoryError"
	}
	return "OSError"
}

var (
	errJSON    = errors.New("json")
	errValue   = errors.New("value")
	errUnicode = errors.New("unicode")
)

// count adds one to the beat's counter for kind and returns a refusal when
// that is over the limit. No beat id: nothing is counted. A counter that
// cannot be read or written refuses: a limit that quietly stops counting is
// not a limit.
func (g guard) count(kind string) string {
	beat := g.getenv("CHECKIN_BEAT_ID")
	if beat == "" {
		return ""
	}
	home := g.getenv("FLEET_HOME")
	if !beatIDRE.MatchString(beat) || home == "" {
		return "the beat's counter is not configured"
	}
	limit := g.limit(kind)
	over, err := bump(filepath.Join(home, "state", "checkin-counts"), beat+".json", kind, limit)
	if err != nil {
		return "the beat's counter could not be updated (" + pyError(err) + ")"
	}
	if !over {
		return ""
	}
	syslogWarn(fmt.Sprintf("beat %s: %s limit %d reached; call refused", beat, kind, limit))
	return fmt.Sprintf("this beat has reached its limit for %s (%d). It is a safety limit, not an outage: "+
		"stop and let the next beat continue.", strings.ReplaceAll(kind, "_", " "), limit)
}

// bump adds one to kind in the counter file under an exclusive lock, records
// kind in "tripped" when it goes over limit, and reports whether it did.
func bump(dir, name, kind string, limit int) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	// #nosec G304 -- FLEET_HOME from run-checkin plus a checked beat id.
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return false, err
	}
	raw, err := readAll(f)
	if err != nil {
		return false, err
	}
	if !utf8.Valid(raw) {
		return false, errUnicode
	}
	data := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&v) != nil || dec.More() {
			return false, errJSON
		}
		m, ok := v.(map[string]any)
		if !ok {
			return false, errValue
		}
		data = m
	}
	n := 0
	switch x := data[kind].(type) {
	case nil:
		if _, present := data[kind]; present {
			return false, errValue
		}
	case bool:
		if x {
			n = 1
		}
	case json.Number:
		i, err := strconv.Atoi(string(x))
		if err != nil {
			return false, errValue
		}
		n = i
	default:
		return false, errValue
	}
	n++
	data[kind] = n
	over := n > limit
	if over {
		tripped, ok := data["tripped"].([]any)
		if !ok {
			tripped = []any{}
		}
		has := false
		for _, t := range tripped {
			if t == kind {
				has = true
			}
		}
		if !has {
			tripped = append(tripped, kind)
		}
		data["tripped"] = tripped
	}
	out, err := json.Marshal(data)
	if err != nil {
		return false, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return false, err
	}
	if err := f.Truncate(0); err != nil {
		return false, err
	}
	if _, err := f.Write(out); err != nil {
		return false, err
	}
	return over, nil
}

func readAll(f *os.File) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(f)
	return buf.Bytes(), err
}
