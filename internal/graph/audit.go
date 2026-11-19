package graph

import (
	"strconv"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/audit"
)

// Every call here that changes a mailbox writes an audit event (see
// internal/audit): mail sent, mail moved, a folder made. They are written at
// the client, not at each command, so cti-mailer, cti-alert, cti-mailbox and
// anything added later are covered without remembering to. Reads are not
// audited, and neither is a rehearsal: --dry-run never reaches these methods.
// No subject, body or address of a sender goes in an event; recipients do,
// because "who was this sent to" is the question an audit answers.

func auditMail(action, target, detail string, err error) {
	outcome := audit.Success
	if err != nil {
		outcome = audit.Failure
		if detail != "" {
			detail += "; "
		}
		detail += "error: request failed"
	}
	audit.Emit(audit.Event{Action: action, Target: target, Outcome: outcome, Detail: detail})
}

func recipients(req SendMailRequest) string {
	all := append(append([]string{}, req.To...), req.CC...)
	return strings.Join(all, ",")
}

// tail is the last n characters of an opaque id: enough to find the message in
// the mailbox's own logs, not enough to be a handle.
func tail(id string, n int) string {
	if len(id) <= n {
		return id
	}
	return id[len(id)-n:]
}

func sendDetail(req SendMailRequest) string {
	return "from=" + req.From + "; attachments=" + strconv.Itoa(len(req.Attachments))
}
