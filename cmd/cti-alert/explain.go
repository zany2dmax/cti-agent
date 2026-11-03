package main

import (
	"fmt"
	"regexp"
	"strings"
)

// explain is the paragraph at the top of the alert that says, in plain words,
// what the problem is. The rest of the mail is evidence (systemd's verdict, 40
// journal lines); this is the part a person reads first, and it exists because
// the evidence alone had to be decoded.
//
// It is built from what cti-alert already holds - the unit's name, systemd's
// result, the journal tail and any --reason - and nothing here calls out or
// guesses beyond a short table of known messages. When it cannot say more it
// quotes the last error line verbatim rather than inventing a cause.
func explain(f failure) string {
	what := unitPurpose(f.Unit)

	// The orchestrator and the lanes that hold themselves already wrote the
	// message. Lead with it, whole, instead of burying it in a table row.
	switch {
	case f.isEscalation() && f.Reason != "":
		return "The orchestrator needs you to look at something: " + f.Reason
	case f.isHold() && f.Reason != "":
		return fmt.Sprintf("%s stopped itself on purpose: %s", capFirst(what), f.Reason)
	case f.isTest():
		return "This is a test of the alert path; " + what + " is healthy and nothing needs doing."
	}

	var b strings.Builder
	b.WriteString(capFirst(what))
	b.WriteString(" ")
	b.WriteString(resultPhrase(f))
	b.WriteString(".")

	line := ""
	if !strings.HasPrefix(f.Journal, "(journal unavailable") {
		line = keyLine(f.Journal)
	}
	if line != "" {
		if hint := hintFor(line); hint != "" {
			b.WriteString(" ")
			b.WriteString(hint)
			b.WriteString(".")
		}
		b.WriteString(` The last error it logged was: "`)
		b.WriteString(line)
		b.WriteString(`"`)
	} else if f.Journal == "" || strings.HasPrefix(f.Journal, "(journal unavailable") {
		b.WriteString(" The journal could not be read from here, so the cause is not shown.")
	} else {
		b.WriteString(" Nothing in its last journal lines looks like an error; " +
			"open the full journal below.")
	}
	return b.String()
}

var unitPurposes = []struct{ match, what string }{
	{"digest", "the daily threat-intel digest"},
	{"weekly", "the Monday fleet-exposure weekly report"},
	{"patchtuesday", "the Patch Tuesday report"},
	{"mailbox", "mailbox cleanup"},
	{"appowners", "the daily mail of scanner reports to application owners"},
	{"appscan", "the application-security weekly report"},
	{"domains", "the weekly domains check"},
	{"scout", "the threat-feed scout"},
	{"checkin", "the orchestrator's check-in"},
	{"alert", "the alert sender"},
}

func unitPurpose(unit string) string {
	u := strings.ToLower(unit)
	for _, p := range unitPurposes {
		if strings.Contains(u, p.match) {
			return p.what
		}
	}
	return "the " + strings.TrimSuffix(strings.TrimPrefix(unit, "cti-agent-"), ".service") + " lane"
}

func resultPhrase(f failure) string {
	switch f.Result {
	case "timeout":
		return "ran past its time limit and systemd stopped it"
	case "exit-code":
		return "exited with an error (status " + f.ExitCode + ")"
	case "signal":
		return "was killed by a signal"
	case "core-dump":
		return "crashed"
	case "oom-kill":
		return "was killed for running out of memory"
	case "start-limit-hit":
		return "was restarted too often and systemd gave up on it"
	case "resources":
		return "could not start because systemd lacked a resource it needed"
	case "", "unknown", "success":
		return "was reported as failed, but systemd records no failure for it"
	}
	return "ended with systemd result '" + f.Result + "'"
}

var (
	// journalPrefix is "Nov 03 07:04:48 host tag[123]: ".
	journalPrefix = regexp.MustCompile(`^\w{3} +\d+ +[\d:]+ +\S+ +([^:\s]+?)(?:\[\d+\])?: +`)
	errorWords    = regexp.MustCompile(`(?i)error|fail|fatal|denied|refus|timed out|timeout|deadline|missing|cannot|unable|corrupt|panic|exit status|no such|forbidden|unauthori[sz]ed`)
)

// keyLine is the last line the lane itself logged that looks like an error,
// without the journal's date/host prefix. systemd's own bookkeeping lines
// ("Failed with result 'exit-code'.") are skipped: they restate the result,
// not the cause.
func keyLine(journal string) string {
	lines := strings.Split(strings.TrimSpace(journal), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if m := journalPrefix.FindStringSubmatch(l); m != nil {
			if strings.HasPrefix(m[1], "systemd") {
				continue
			}
			l = l[len(m[0]):]
		}
		if errorWords.MatchString(l) {
			return truncate(l, 300)
		}
	}
	return ""
}

var hints = []struct {
	re  *regexp.Regexp
	say string
}{
	{regexp.MustCompile(`(?i)missing required environment`), "A required setting is missing from fleet.env - the line quoted names which"},
	{regexp.MustCompile(`(?i)AADSTS|invalid_client|\b401\b|unauthori[sz]ed`), "Signing in failed; a client secret or API token has probably expired or been rotated"},
	{regexp.MustCompile(`(?i)\b403\b|forbidden|Authorization_RequestDenied|access is denied`), "The service refused the request; the app registration or account probably lacks a permission, or an access policy excludes this mailbox"},
	{regexp.MustCompile(`(?i)\b429\b|rate.?limit|throttl`), "A service throttled the requests"},
	{regexp.MustCompile(`(?i)deadline exceeded|timed out|timeout`), "A call to Graph, Qualys, Jira or another service did not answer in time"},
	{regexp.MustCompile(`(?i)no such host|connection refused|network is unreachable|i/o timeout`), "The box could not reach a service (DNS or network)"},
	{regexp.MustCompile(`(?i)no space left`), "The disk is full"},
	{regexp.MustCompile(`(?i)permission denied|avc:`), "The service account was not allowed to read or write something; check file permissions and SELinux"},
	{regexp.MustCompile(`(?i)corrupt`), "A state file is damaged"},
	{regexp.MustCompile(`(?i)refusing to`), "The lane stopped itself on purpose, and the line quoted says why"},
}

func hintFor(line string) string {
	for _, h := range hints {
		if h.re.MatchString(line) {
			return h.say
		}
	}
	return ""
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
