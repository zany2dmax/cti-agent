package jira

import (
	"errors"

	"github.com/zany2dmax/cti-agent/internal/audit"
)

// Every call here that changes Jira writes an audit event (see internal/audit):
// what was done, to which project or issue, and whether it worked. They are
// written at the client, not at each caller, so a new command that files or
// edits a ticket is audited without remembering to. Reads are not audited.
// Nothing from the ticket's text goes in the event: the key and the kind of
// change are enough to find the rest in Jira.

func auditJira(action, target, detail string, err error) {
	outcome := audit.Success
	if err != nil {
		outcome = audit.Failure
		if detail != "" {
			detail += "; "
		}
		detail += "error: " + errClass(err)
	}
	audit.Emit(audit.Event{Action: action, Target: target, Outcome: outcome, Detail: detail})
}

// errClass says what kind of failure it was without echoing text a remote
// server controls.
func errClass(err error) string {
	var ce *ContinuationError
	if errors.As(err, &ce) {
		return "issue created, a continuation comment failed"
	}
	return "request failed"
}
