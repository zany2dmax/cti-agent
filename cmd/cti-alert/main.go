// Command cti-alert tells the operator that a fleet unit failed.
//
// systemd invokes it via OnFailure=; it is not meant to be run by hand,
// though it is safe to.
//
// WHY THIS EXISTS
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
	body := renderHTML(f)
	subject := fmt.Sprintf("[CTI FLEET FAILED] %s on %s", f.Unit, f.Host)

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
	IsDigest  bool // the digest failing has a consequence the others do not
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
	msg := fmt.Sprintf("%s failed (result=%s exit=%s) on %s at %s",
		f.Unit, f.Result, f.ExitCode, f.Host, f.When)
	if _, err := run(10*time.Second, board, "post", "@systemd", "@operator", "ERROR", msg); err != nil {
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
		HighImportance: f.IsDigest,
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
	if f.IsDigest {
		consequence = "NO THREAT-INTEL EMAIL WILL ARRIVE. An absent digest looks " +
			"exactly like a quiet day, so treat the silence as unexplained."
	}
	return fmt.Sprintf(`%s failed on %s at %s

systemd result: %s
exit status:    %s
restarts:       %s

%s

Last %s journal lines:

%s

Next steps on the box:
  systemctl status %s
  journalctl -u %s -n 100 --no-pager
  sudo ausearch -m avc -ts recent          # SELinux denials
  sudo cti-agent run-digest daily --dry-run`,
		f.Unit, f.Host, f.When, f.Result, f.ExitCode, f.NRestarts,
		consequence, journalLines, f.Journal, f.Unit, f.Unit)
}

func renderHTML(f failure) string {
	consequence := "Check what this unit is responsible for before assuming it is harmless."
	if f.IsDigest {
		consequence = "<b>No threat-intel email will arrive.</b> An absent digest looks " +
			"exactly like a quiet day, so treat the silence as unexplained until you " +
			"have checked."
	}
	e := html.EscapeString
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="margin:0;padding:16px;background:#eef1f5">
<table width="100%%" cellpadding="0" cellspacing="0" role="presentation">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:680px;background:#fff;border-radius:6px;overflow:hidden">
  <tr><td style="background:#b3001b;padding:14px 18px;font:700 15px
                 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
    CTI fleet failure</td></tr>
  <tr><td style="padding:16px 18px;font:400 14px/1.55 -apple-system,Segoe UI,
                 Helvetica,Arial,sans-serif;color:#1a202c">
    <p style="margin:0 0 12px 0"><code>%s</code> failed on <b>%s</b> at %s.</p>
    <table cellpadding="4" cellspacing="0"
           style="font:400 13px -apple-system,Segoe UI,Arial,sans-serif;color:#2d3748">
      <tr><td><b>systemd result</b></td><td><code>%s</code></td></tr>
      <tr><td><b>exit status</b></td><td><code>%s</code></td></tr>
      <tr><td><b>restarts</b></td><td><code>%s</code></td></tr>
    </table>
    <p style="margin:12px 0 0 0;padding:10px 12px;background:#fdecee;
              border-left:4px solid #b3001b">%s</p>
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
sudo ausearch -m avc -ts recent
sudo cti-agent run-digest daily --dry-run</pre>
  </td></tr>
</table></td></tr></table></body></html>`,
		e(f.Unit), e(f.Host), e(f.When), e(f.Result), e(f.ExitCode), e(f.NRestarts),
		consequence, journalLines, e(f.Journal), e(f.Unit), e(f.Unit))
}
