// Command cti-alert tells the operator that a fleet unit failed.
//
// systemd invokes it via OnFailure=; it is not meant to be run by hand,
// though it is safe to.
//
// # WHY THIS EXISTS
//
// The fleet's whole premise is that a quiet inbox means a quiet day. That only
// holds if a broken pipeline is loud. Without this, a failed digest timer
// produces exactly the same observable result as "no new CVEs" - no email -
// and the failure can sit unnoticed for weeks. Silence has to mean something,
// so a failure has to break the silence.
//
// It writes to two channels and always exits 0:
//
//	the message board  - always works, no network, the orchestrator relays it
//	email              - reaches a phone, but may be broken by the same fault
//
// Exiting non-zero would mark this unit failed too, which makes
// `systemctl --failed` misleading about what actually broke. The alert unit
// deliberately has no OnFailure of its own: an alert that alerts on its own
// failure loops every 30 minutes.
package main

import (
	"context"
	"flag"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

const journalLines = "40"

func main() {
	unit := flag.String("unit", "", "the systemd unit that failed (required)")
	dryRun := flag.Bool("dry-run", false, "print what would be sent, send nothing")
	// A lane can be stopped on purpose - a budget hold, say - which is worth an
	// email but is not a failure. Without these two flags such a notice would
	// arrive titled FAILED and quoting a journal that shows the unit succeeded,
	// which trains the reader to distrust the alerts that do matter.
	kind := flag.String("kind", "FAILED",
		"headline word: FAILED for a crash, HOLD for a deliberate stop. TEST is inferred when the named unit is healthy")
	reason := flag.String("reason", "",
		"one-line explanation shown above the systemd detail")
	flag.Parse()

	// systemd passes the unit as a bare argument via `ExecStart=... %i`, so
	// accept both forms rather than making the unit file fragile.
	name := *unit
	if name == "" && flag.NArg() > 0 {
		name = flag.Arg(0)
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "cti-alert: no unit given; pass --unit or one argument")
		os.Exit(2) // a usage error is worth failing on; a send error is not
	}

	loadEnvFile()

	f := gather(name)
	f.Kind = strings.ToUpper(*kind)
	f.Reason = *reason

	// An alert whose subject unit is demonstrably healthy was started by hand,
	// not by OnFailure=. Saying "failed (result=success exit=0)" in that case
	// contradicts itself in the same sentence - and because the orchestrator
	// reads the board every beat, it would open an incident for a failure that
	// never happened. Testing the alert path must not manufacture the thing it
	// is testing for.
	if f.Kind == "FAILED" && f.ExitCode == "0" &&
		(f.Result == "success" || f.Result == "" || f.Result == "unknown") {
		f.Kind = "TEST"
		if f.Reason == "" {
			f.Reason = "manual test of the alert path - " + f.Unit +
				" is healthy (result=success, exit=0). No action needed."
		}
	}
	body := renderHTML(f)
	subject := fmt.Sprintf("[CTI FLEET %s] %s on %s", f.Kind, f.Unit, f.Host)

	// Board first: it needs nothing external, so it is the channel most
	// likely to survive whatever caused the failure.
	boardPosted := postToBoard(f)

	if *dryRun {
		fmt.Println("DRY RUN - nothing sent")
		fmt.Printf("subject: %s\n", subject)
		fmt.Printf("board:   %v\n", boardPosted)
		fmt.Println(renderText(f))
		return
	}

	if reqID, err := sendEmail(subject, body, f); err != nil {
		// This is the bad case: the pipeline failed AND we cannot say so.
		// Dump everything to the journal, which systemd has already captured.
		fmt.Fprintf(os.Stderr, "cti-alert: COULD NOT EMAIL the operator about %s: %v\n", f.Unit, err)
		fmt.Fprintf(os.Stderr, "cti-alert: the original failure may itself be the mail path\n")
		fmt.Fprintf(os.Stderr, "cti-alert: board posted: %v\n", boardPosted)
		fmt.Fprintln(os.Stderr, renderText(f))
	} else {
		fmt.Printf("cti-alert: emailed the operator about %s (request-id %s)\n", f.Unit, reqID)
	}

	// Always 0. See the package comment.
	os.Exit(0)
}

// failure is everything worth telling a human about one failed unit.
type failure struct {
	Unit      string
	Host      string
	When      string
	Result    string // systemd's own verdict: exit-code, timeout, signal...
	ExitCode  string
	NRestarts string
	Journal   string
	IsDigest  bool   // the digest failing has a consequence the others do not
	Kind      string // FAILED, HOLD or TEST - they must not look alike
	Reason    string // set for HOLD and TEST; empty for a crash, where the journal is the story
}

func gather(unit string) failure {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	f := failure{
		Unit:      unit,
		Host:      host,
		When:      time.Now().Format("2006-01-02 15:04:05 MST"),
		Result:    systemctlShow(unit, "Result"),
		ExitCode:  systemctlShow(unit, "ExecMainStatus"),
		NRestarts: systemctlShow(unit, "NRestarts"),
		Journal:   journal(unit),
		IsDigest:  strings.Contains(unit, "digest") || strings.Contains(unit, "weekly"),
	}
	return f
}

// systemctlShow reads one property. A missing systemctl or unknown property is
// not worth failing over - the alert is still worth sending without it.
func systemctlShow(unit, prop string) string {
	out, err := run(3*time.Second, "systemctl", "show", "-p", prop, "--value", unit)
	if err != nil || strings.TrimSpace(out) == "" {
		return "unknown"
	}
	return strings.TrimSpace(out)
}

func journal(unit string) string {
	out, err := run(10*time.Second, "journalctl", "-u", unit, "-n", journalLines, "--no-pager")
	if err != nil || strings.TrimSpace(out) == "" {
		return "(journal unavailable: " + errText(err) + ")"
	}
	return strings.TrimSpace(out)
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- name is a compile-time constant at both call sites
	// ("systemctl" and "journalctl"); nothing computes it. Arguments go
	// through argv, not a shell, so a unit name containing shell
	// metacharacters is passed as one opaque argument rather than
	// interpreted. The unit name itself is a systemd specifier supplied by
	// the unit that invoked this alerter.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func errText(err error) string {
	if err == nil {
		return "no output"
	}
	return err.Error()
}

// postToBoard appends one line to the fleet message board, so the
// orchestrator surfaces the failure on its next heartbeat even if email fails.
func postToBoard(f failure) bool {
	code := envOr("FLEET_CODE", "/opt/cti-agent")
	board := filepath.Join(code, "bin", "fleet-board")
	if _, err := os.Stat(board); err != nil {
		return false
	}
	// A hold is not an ERROR on the board either. The orchestrator reads these
	// lines on its next beat and should not open an incident over its own brake.
	level, msg := "ERROR", fmt.Sprintf("%s failed (result=%s exit=%s) on %s at %s",
		f.Unit, f.Result, f.ExitCode, f.Host, f.When)
	if f.isHold() {
		level, msg = "INFO", fmt.Sprintf("%s is holding on %s at %s: %s",
			f.Unit, f.Host, f.When, f.Reason)
	} else if f.isTest() {
		level, msg = "INFO", fmt.Sprintf("alert path tested against %s on %s at %s - %s is healthy, no incident",
			f.Unit, f.Host, f.When, f.Unit)
	}
	if _, err := run(10*time.Second, board, "post", "@systemd", "@operator", level, msg); err != nil {
		return false
	}
	return true
}

func sendEmail(subject, htmlBody string, f failure) (string, error) {
	tenant := os.Getenv("TENANT_ID")
	clientID := os.Getenv("CLIENT_ID")
	secret := os.Getenv("CLIENT_SECRET")
	from := os.Getenv("GRAPH_MAILBOX")
	to := firstNonEmptyEnv("FLEET_OPERATOR_EMAIL", "DIGEST_TO")

	var missing []string
	for name, v := range map[string]string{
		"TENANT_ID": tenant, "CLIENT_ID": clientID, "CLIENT_SECRET": secret,
		"GRAPH_MAILBOX": from,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if to == "" {
		missing = append(missing, "FLEET_OPERATOR_EMAIL (or DIGEST_TO)")
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("cannot send: missing %s", strings.Join(missing, ", "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := graph.New(tenant, clientID, secret)
	return c.SendMail(ctx, graph.SendMailRequest{
		From:    from,
		To:      splitList(to),
		Subject: subject,
		HTML:    htmlBody,
		// A failed digest means intel is not reaching anyone. That earns high
		// importance; a scout sweep failing does not.
		// High importance is reserved for a broken digest. A hold is never
		// urgent - flagging one would spend the signal that makes a real
		// digest failure stand out.
		HighImportance: f.IsDigest && !f.notFailure(),
	})
}

// loadEnvFile reads fleet.env so a manual run works without exporting
// everything. systemd already supplies these via EnvironmentFile, and
// existing environment always wins.
func loadEnvFile() {
	path := os.Getenv("FLEET_ENV")
	if path == "" {
		path = filepath.Join(envOr("FLEET_HOME", "/var/lib/cti-agent"), "fleet.env")
	}
	// #nosec G304 -- path is FLEET_ENV, or fleet.env under FLEET_HOME. Both
	// are service configuration; the file itself holds the credentials this
	// process needs, so reading it is the point.
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func renderText(f failure) string {
	consequence := "Check what this unit is responsible for before assuming it is harmless."
	verb := "failed"
	reason := ""

	if f.isTest() {
		verb = "alert path tested against"
		consequence = "This is a test. The unit is healthy and nothing failed. " +
			"Receiving this confirms the alert path works end to end: systemd " +
			"started the alerter, it read the journal, and Graph delivered the mail."
	} else if f.isHold() {
		// A hold is the brake working. Saying so plainly is the difference
		// between an operator who ignores it and one who goes looking for a
		// crash that never happened.
		verb = "is holding"
		consequence = "Nothing is broken. The lane stopped itself and will resume " +
			"on its own once the condition clears. No action is needed unless " +
			"this repeats for longer than you expect."
	} else if f.IsDigest {
		consequence = "NO THREAT-INTEL EMAIL WILL ARRIVE. An absent digest looks " +
			"exactly like a quiet day, so treat the silence as unexplained."
	}
	if f.Reason != "" {
		reason = "Reason: " + f.Reason + "\n\n"
	}

	return fmt.Sprintf(`%s %s on %s at %s

%ssystemd result: %s
exit status:    %s
restarts:       %s

%s

Last %s journal lines:

%s

Next steps on the box:
  systemctl status %s
  journalctl -u %s -n 100 --no-pager
  sudo cti-agent cti-budget status         # ceilings, cooldown, beats used
  sudo ausearch -m avc -ts recent          # SELinux denials`,
		f.Unit, verb, f.Host, f.When, reason, f.Result, f.ExitCode, f.NRestarts,
		consequence, journalLines, f.Journal, f.Unit, f.Unit)
}

// isHold separates a deliberate stop from a crash. Everything that is not an
// explicit HOLD is treated as a failure, so a malformed --kind errs toward
// alarming rather than reassuring.
func (f failure) isHold() bool { return f.Kind == "HOLD" }

// isTest marks an alert triggered by hand against a healthy unit. Like a hold,
// it is not a failure - so it must not be red, not be high importance, and not
// land on the board as an ERROR the orchestrator will act on.
func (f failure) isTest() bool { return f.Kind == "TEST" }

// notFailure covers every kind that should be reported calmly. Anything not
// explicitly listed is treated as a real failure, so an unrecognised --kind
// errs toward alarming rather than reassuring.
func (f failure) notFailure() bool { return f.isHold() || f.isTest() }

func renderHTML(f failure) string {
	consequence := "Check what this unit is responsible for before assuming it is harmless."
	// Red for a crash, amber for a deliberate stop. If every fleet email is
	// the same alarming red, the colour stops carrying information.
	banner, accent, tint := "CTI fleet failure", "#b3001b", "#fdecee"
	verb, reasonRow := "failed", ""

	if f.isTest() {
		banner, accent, tint = "CTI fleet alert test", "#1f6f43", "#e9f7ef"
		verb = "alert path tested against"
		consequence = "<b>This is a test.</b> The unit is healthy and nothing " +
			"failed. Receiving this confirms the alert path works end to end."
	} else if f.isHold() {
		banner, accent, tint = "CTI fleet on hold", "#8a5a00", "#fff7e6"
		verb = "is holding"
		consequence = "<b>Nothing is broken.</b> The lane stopped itself and will " +
			"resume once the condition clears. No action is needed unless this " +
			"repeats for longer than you expect."
	} else if f.IsDigest {
		consequence = "<b>No threat-intel email will arrive.</b> An absent digest looks " +
			"exactly like a quiet day, so treat the silence as unexplained until you " +
			"have checked."
	}
	e := html.EscapeString
	if f.Reason != "" {
		reasonRow = `<tr><td><b>reason</b></td><td>` + e(f.Reason) + `</td></tr>`
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="margin:0;padding:16px;background:#eef1f5">
<table width="100%%" cellpadding="0" cellspacing="0" role="presentation">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:680px;background:#fff;border-radius:6px;overflow:hidden">
  <tr><td style="background:%s;padding:14px 18px;font:700 15px
                 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
    %s</td></tr>
  <tr><td style="padding:16px 18px;font:400 14px/1.55 -apple-system,Segoe UI,
                 Helvetica,Arial,sans-serif;color:#1a202c">
    <p style="margin:0 0 12px 0"><code>%s</code> %s on <b>%s</b> at %s.</p>
    <table cellpadding="4" cellspacing="0"
           style="font:400 13px -apple-system,Segoe UI,Arial,sans-serif;color:#2d3748">
      %s
      <tr><td><b>systemd result</b></td><td><code>%s</code></td></tr>
      <tr><td><b>exit status</b></td><td><code>%s</code></td></tr>
      <tr><td><b>restarts</b></td><td><code>%s</code></td></tr>
    </table>
    <p style="margin:12px 0 0 0;padding:10px 12px;background:%s;
              border-left:4px solid %s">%s</p>
  </td></tr>
  <tr><td style="padding:0 18px 14px 18px">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin-bottom:6px">LAST %s JOURNAL LINES</div>
    <pre style="margin:0;padding:10px;background:#f4f5f7;border-radius:4px;
                font:400 11px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;
                color:#1a202c;overflow-x:auto;white-space:pre-wrap">%s</pre>
  </td></tr>
  <tr><td style="padding:0 18px 18px 18px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin:12px 0 6px 0">NEXT STEPS ON THE BOX</div>
    <pre style="margin:0;font:400 12px/1.6 ui-monospace,SFMono-Regular,Menlo,
                monospace;color:#2d3748">systemctl status %s
journalctl -u %s -n 100 --no-pager
sudo cti-agent cti-budget status
sudo ausearch -m avc -ts recent</pre>
  </td></tr>
</table></td></tr></table></body></html>`,
		accent, banner,
		e(f.Unit), verb, e(f.Host), e(f.When),
		reasonRow, e(f.Result), e(f.ExitCode), e(f.NRestarts),
		tint, accent, consequence,
		journalLines, e(f.Journal), e(f.Unit), e(f.Unit))
}
