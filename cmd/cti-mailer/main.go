// Command cti-mailer is the fleet's single outbound mail channel.
//
// A port of lanes/mailer.py, flag for flag and output for output, so the
// runners that call it do not have to change and the two can be compared
// side by side before the Python one is retired.
//
//	cti-mailer --html digest.html                            # -> DIGEST_TO
//	cti-mailer --html d.html --text d.txt --subject "..."
//	cti-mailer --to-operator --subject "Approve?" --message "..." --board-id q17
//	cti-mailer --html d.html --cc a@example.com,b@example.com
//	cti-mailer --html d.html --dry-run                       # render + validate only
//	cti-mailer --check                                       # verify token + roles
//
// # WHY THIS IS GO NOW
//
// This is the only component that sends mail, and it holds the FLEET_ALLOW_TO
// recipient gate - the control that decides who receives a document naming
// exploitable machines. It was the most security-relevant code in the
// repository sitting outside gosec and govulncheck, for no better reason than
// that it started in Python. It needs no SQLite, which is the only thing
// keeping the other lanes there.
//
// The behaviour is deliberately identical. A port that also improves things
// cannot be verified by diffing old against new output, and this is the one
// component where a subtle change is discovered by somebody NOT receiving a
// security finding.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/mailer"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/version"
)

const (
	exitOK      = 0
	exitFailure = 1

	// maxInlineAttachment matches what mailer.py enforced. Graph accepts more
	// via an upload session, which this does not implement: an attachment
	// that large is a different feature, not a bigger number.
	maxInlineAttachment = 3_000_000
)

// logf writes the operator-facing line. stderr, so stdout stays a clean JSON
// document for the runners that parse it.
func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[mailer] "+format+"\n", a...)
}

func die(format string, a ...any) int {
	logf("ERROR: "+format, a...)
	return exitFailure
}

// repeatable collects a flag that may appear more than once, like --attach.
type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

func main() { os.Exit(run()) }

func run() int {
	var attach repeatable
	htmlPath := flag.String("html", "", "rendered digest to send")
	message := flag.String("message", "",
		"short plain-text body, wrapped in minimal HTML - for escalations, not digests")
	textPath := flag.String("text", "",
		"plain-text alternative. Accepted and logged; Graph sends one body, so "+
			"this is not transmitted. Kept because the runners pass it")
	subject := flag.String("subject", "", "subject line")
	to := flag.String("to", "", "comma-separated; defaults to DIGEST_TO")
	cc := flag.String("cc", "",
		"comma-separated; defaults to DIGEST_CC. Subject to the same "+
			"FLEET_ALLOW_TO gate as --to")
	toOperator := flag.Bool("to-operator", false,
		"send to FLEET_OPERATOR_EMAIL. Pre-approved: telling the operator "+
			"something is not an outward-facing send.")
	fromMailbox := flag.String("from-mailbox", "", "sending mailbox; defaults to GRAPH_MAILBOX")
	boardID := flag.String("board-id", "",
		"board line id, so your reply can be matched back to the question")
	dryRun := flag.Bool("dry-run", false, "render and validate, send nothing")
	requireApproval := flag.Bool("require-approval", false,
		"refuse unless --approve is also passed (off-cycle sends)")
	approve := flag.Bool("approve", false,
		"the operator approved this specific off-cycle send")
	saveToSent := flag.String("save-to-sent", "true", "keep a copy in Sent Items")
	check := flag.Bool("check", false, "verify configuration, token and granted roles")
	flag.Var(&attach, "attach", "file to attach (repeatable, keep under ~3MB total)")
	flag.Parse()

	// fleet.env, so a run by hand or by cron gets the same settings systemd
	// gives it. Existing environment always wins.
	fleetenv.Load()

	mailbox := *fromMailbox
	if mailbox == "" {
		mailbox = os.Getenv("GRAPH_MAILBOX")
	}

	if *check {
		// Report every missing setting at once. Dying on the first turns
		// first-time configuration into a series of one-line errors, each
		// needing another run to reveal the next.
		return preflight(mailbox)
	}

	if mailbox == "" {
		return die("GRAPH_MAILBOX is not set in %s - set it there, or pass "+
			"--from-mailbox", safelog.Line(fleetenv.Path()))
	}
	if (*htmlPath != "") == (*message != "") {
		return die("pass exactly one of --html (a rendered digest) or --message " +
			"(a short escalation)")
	}
	if *htmlPath != "" {
		if _, err := os.Stat(*htmlPath); err != nil {
			return die("%s does not exist", safelog.Line(*htmlPath))
		}
	}
	if *textPath != "" {
		// Named so the operator is not left wondering why it had no effect.
		logf("note   : --text is recorded but not transmitted; Graph sends one body")
	}

	operator := strings.TrimSpace(os.Getenv("FLEET_OPERATOR_EMAIL"))
	recipients, copies, err := mailer.Audience{
		ToOperator:  *toOperator,
		ToFlag:      *to,
		CCFlag:      *cc,
		DigestTo:    os.Getenv("DIGEST_TO"),
		DigestCC:    os.Getenv("DIGEST_CC"),
		Operator:    operator,
		AllowRaw:    os.Getenv("FLEET_ALLOW_TO"),
		CCFromAllow: mailer.Truthy(os.Getenv("DIGEST_CC_FROM_ALLOW_TO")),
	}.Resolve()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}

	if err := mailer.CheckAllowed(recipients, copies,
		os.Getenv("FLEET_ALLOW_TO"), os.Getenv("DIGEST_TO"),
		operator, *approve); err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	if *requireApproval && !*approve {
		return die("this send is marked as requiring approval and --approve was not passed")
	}

	var body string
	if *htmlPath != "" {
		// #nosec G304 -- an operator-supplied path to a file this fleet just
		// rendered. Reading it is the point of the command.
		b, err := os.ReadFile(*htmlPath)
		if err != nil {
			return die("reading %s: %s", safelog.Line(*htmlPath), safelog.Line(err.Error()))
		}
		body = string(b)
	} else {
		replyTo := os.Getenv("CTI_REPLY_MAILBOX")
		if replyTo == "" {
			replyTo = mailbox
		}
		body = mailer.EscalationHTML(*message, *boardID, replyTo)
	}

	subj := mailer.Subject(*subject, *boardID, *message != "", time.Now())
	attachments, skipped := loadAttachments(attach)
	for _, s := range skipped {
		logf("%s", s)
	}

	logf("from   : %s", safelog.Line(mailbox))
	logf("to     : %s", safelog.Line(strings.Join(recipients, ", ")))
	logf("subject: %s", safelog.Line(subj))
	logf("size   : %d bytes html, %d attachment(s)", len(body), len(attachments))

	if *dryRun {
		logf("DRY RUN - nothing sent")
		out := map[string]any{
			"dry_run": true, "subject": subj,
			"to": recipients, "cc": orEmpty(copies),
			"mode": "message",
		}
		if *htmlPath != "" {
			out["mode"] = "html"
			abs, err := filepath.Abs(*htmlPath)
			if err != nil {
				abs = *htmlPath
			}
			out["html"] = abs
		} else {
			// No file to point at in message mode, so hand back the rendered
			// body: the orchestrator should be able to read what it almost sent.
			out["body"] = body
		}
		emit(out)
		return exitOK
	}

	save := strings.EqualFold(strings.TrimSpace(*saveToSent), "true")
	g := graph.New(os.Getenv("TENANT_ID"), os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := g.SendMail(ctx, graph.SendMailRequest{
		From:            mailbox,
		To:              recipients,
		CC:              copies,
		Subject:         subj,
		HTML:            body,
		HighImportance:  mailer.HighImportance(subj),
		Attachments:     attachments,
		SaveToSentItems: &save,
	})
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	reqID := res.RequestID
	if reqID == "" {
		reqID = "unknown"
	}

	// sendMail returns 202 with no body, so there is no message id to capture.
	// request-id is what you give Microsoft support when a mail goes missing.
	// The status is the one Graph actually returned, not the one expected:
	// reporting 202 unconditionally would describe the code rather than the
	// call.
	logf("sent - HTTP %d, request-id %s", res.Status, safelog.Line(reqID))
	emit(map[string]any{
		"sent": true, "status": res.Status, "request_id": reqID,
		"subject": subj, "to": recipients, "cc": orEmpty(copies),
		"ts": time.Now().UTC().Format(time.RFC3339),
	})
	return exitOK
}

// orEmpty renders a nil slice as [] rather than null. The runners parse this
// with json.load and a null where a list belongs is a needless special case.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func emit(v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		logf("could not encode the result: %s", safelog.Line(err.Error()))
		return
	}
	fmt.Println(string(b))
}

// loadAttachments reads what it can and explains what it skipped.
//
// A missing or oversized attachment does not fail the send. The digest is the
// payload; the raw report is supporting evidence, and losing the evidence is
// not a reason to withhold the finding. Every skip is stated, because an
// attachment that silently did not arrive is worse than one that never
// existed.
func loadAttachments(paths []string) ([]graph.Attachment, []string) {
	var out []graph.Attachment
	var skipped []string
	for _, p := range paths {
		// #nosec G304 -- operator-supplied attachment path.
		b, err := os.ReadFile(p)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("skipping missing attachment %s",
				safelog.Line(p)))
			continue
		}
		if len(b) > maxInlineAttachment {
			skipped = append(skipped, fmt.Sprintf(
				"skipping %s: %d bytes exceeds the inline attachment limit",
				safelog.Line(p), len(b)))
			continue
		}
		ct := "text/plain"
		if strings.HasSuffix(p, ".md") {
			ct = "text/markdown"
		}
		out = append(out, graph.Attachment{
			Name: filepath.Base(p), ContentType: ct, Bytes: b,
		})
	}
	return out, skipped
}

// ---------------------------------------------------------------- --check

// required and optional mirror mailer.py's tables, kept here rather than
// inline so the preflight report and the documentation cannot drift apart.
var required = [][2]string{
	{"TENANT_ID", "Entra tenant the app registration lives in"},
	{"CLIENT_ID", "the app registration"},
	{"CLIENT_SECRET", "its secret - check the expiry date too"},
	{"GRAPH_MAILBOX", "mailbox the fleet reads and sends as"},
	{"FLEET_OPERATOR_EMAIL", "where escalations and failure alerts go"},
}

var optional = [][2]string{
	{"DIGEST_TO", "digest recipients; without it every send needs --to"},
	{"DIGEST_CC", "extra recipients on CC; also gated by FLEET_ALLOW_TO"},
	{"DIGEST_CC_FROM_ALLOW_TO", "true: also CC everyone on the allowlist"},
	{"FLEET_ALLOW_TO", "recipient allowlist, covers To AND Cc; falls back to DIGEST_TO"},
	{"NVD_API_KEY", "without it NVD throttles to 5 requests/30s"},
	{"CLAUDE_CODE_OAUTH_TOKEN", "heartbeat only; digests do not need it"},
}

// versionManifest is written by install-fedora.sh beside fleet.env, so a
// binary can be compared against what the last install believed it put there.
const versionManifest = "/etc/cti-agent/version"

// reportVersion prints what this binary is, and whether it matches the
// install record.
//
// The question "what is production running?" has to be answerable by asking
// production. It previously was not: the installer built from whatever the
// checkout happened to be on and recorded nothing, so a stale checkout left
// binaries predating a feature while the installer printed "Installed".
func reportVersion() {
	v := version.Get()
	logf("version: %s", safelog.Line(v.String()))

	// #nosec G304 -- a fixed path under /etc, not operator-supplied.
	raw, err := os.ReadFile(versionManifest)
	if err != nil {
		// Normal on a workstation, and on a box installed before this
		// existed. Not a warning: an absent manifest is unknown, not wrong.
		return
	}
	recorded := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "commit=") {
			recorded = strings.TrimPrefix(line, "commit=")
		}
	}
	if msg := v.Mismatch(recorded); msg != "" {
		logf("  WARNING: %s", safelog.Line(msg))
	}
}

func preflight(mailbox string) int {
	reportVersion()
	logf("config: %s", safelog.Line(fleetenv.Path()))
	missing := 0
	for _, kv := range required {
		state := "OK  "
		if strings.TrimSpace(os.Getenv(kv[0])) == "" {
			state = "UNSET"
			missing++
		}
		logf("  %s %-22s %s", state, kv[0], kv[1])
	}
	for _, kv := range optional {
		state := "OK  "
		if strings.TrimSpace(os.Getenv(kv[0])) == "" {
			state = "none "
		}
		logf("  %s %-22s %s", state, kv[0], kv[1])
	}
	if missing > 0 {
		logf("")
		logf("%d required setting(s) unset. Edit %s, then rerun.",
			missing, safelog.Line(fleetenv.Path()))
		// Stop here deliberately: requesting a token without a tenant produces
		// an Entra error that describes the wrong problem.
		return exitFailure
	}

	g := graph.New(os.Getenv("TENANT_ID"), os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok, err := g.AccessToken(ctx)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	return reportRoles(tok, mailbox)
}

// requiredRoles maps a capability to the roles that satisfy it.
//
// Mail.ReadWrite SUPERSEDES Mail.Read. Graph's write role includes the read,
// so a tenant that prunes Mail.Read after granting Mail.ReadWrite is correctly
// configured - and a check that required the literal string "Mail.Read" would
// call that install broken. Least privilege and a check that recognises only
// one spelling of it are a bad combination.
var requiredRoles = []struct {
	what         string
	alternatives []string
}{
	{"read the CTI mailbox", []string{"Mail.Read", "Mail.ReadWrite"}},
	{"send the digest", []string{"Mail.Send"}},
}

// Needed only by the mailbox cleanup lane. Reported, never fatal: most installs
// do not run it, and a check that fails for a feature you chose not to use is a
// check people learn to ignore.
var optionalRoles = []struct {
	what         string
	alternatives []string
}{
	{"move mail - cti-mailbox cleanup", []string{"Mail.ReadWrite"}},
}

// usedRoles is every Graph permission this codebase actually calls:
//
//	GET  /users/{mbx}/mailFolders/{f}/messages   Mail.Read or Mail.ReadWrite
//	POST /users/{mbx}/sendMail                   Mail.Send
//	POST /users/{mbx}/messages/{id}/move         Mail.ReadWrite
//
// Anything else consented is unused, and an unused APPLICATION permission on a
// daemon app is blast radius with no upside: a leaked client secret gets
// whatever the tenant consented to, not whatever the code calls.
var usedRoles = map[string]bool{
	"Mail.Read": true, "Mail.ReadWrite": true, "Mail.Send": true,
}

func reportRoles(tok, mailbox string) int {
	tid, appID, roles, err := claims(tok)
	if err != nil {
		return die("could not read the token: %s", safelog.Line(err.Error()))
	}
	logf("tenant=%s app=%s", safelog.Line(tid), safelog.Line(appID))
	shown := "(none)"
	if len(roles) > 0 {
		shown = strings.Join(roles, ", ")
	}
	logf("granted application roles: %s", safelog.Line(shown))

	has := map[string]bool{}
	for _, r := range roles {
		has[r] = true
	}

	ok := true
	for _, rr := range requiredRoles {
		if got := firstPresent(rr.alternatives, has); got != "" {
			logf("  OK       %-16s %s", got, rr.what)
			continue
		}
		logf("  MISSING  %s - %s. Add it in Entra and grant admin consent",
			strings.Join(rr.alternatives, " or "), rr.what)
		ok = false
	}
	for _, rr := range optionalRoles {
		if got := firstPresent(rr.alternatives, has); got != "" {
			logf("  OK       %-16s %s", got, rr.what)
			continue
		}
		logf("  absent   %-16s %s - the cleanup lane will 403. Harmless if you "+
			"are not running it", strings.Join(rr.alternatives, " or "), rr.what)
	}

	// The unused-permission report. Not a style note: an app in front of us had
	// Directory.Read.All, User.Read.All and AuditLog.Read.All consented and
	// called by nothing, which is a far wider grant than the mail access it
	// actually uses.
	var extra []string
	for _, r := range roles {
		if !usedRoles[r] {
			extra = append(extra, r)
		}
	}
	if len(extra) > 0 {
		logf("  UNUSED   %d role(s) granted that this codebase never calls: %s",
			len(extra), safelog.Line(strings.Join(extra, ", ")))
		logf("           Nothing here reads the directory, lists users or reads " +
			"audit logs. Consider removing them - an application permission is " +
			"blast radius whether or not the code uses it.")
	}

	logf("sending mailbox: %s", safelog.Line(mailbox))
	if !ok {
		return exitFailure
	}
	return exitOK
}

func firstPresent(candidates []string, have map[string]bool) string {
	for _, c := range candidates {
		if have[c] {
			return c
		}
	}
	return ""
}

// claims decodes the JWT payload without verifying it.
//
// Verification is not the point and would need the tenant's signing keys: this
// token came from Entra over TLS moments ago, and the question being answered
// is "what did the tenant consent to", not "is this token genuine". A forged
// token would fail at Graph on the next call anyway.
func claims(tok string) (tenant, appID string, roles []string, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return "", "", nil, fmt.Errorf("not a JWT: %d segment(s)", len(parts))
	}
	// base64url, and Entra omits the padding.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", nil, fmt.Errorf("claims are not base64url: %w", err)
	}
	var c struct {
		TID   string   `json:"tid"`
		AppID string   `json:"appid"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", "", nil, fmt.Errorf("claims are not JSON: %w", err)
	}
	return c.TID, c.AppID, c.Roles, nil
}
