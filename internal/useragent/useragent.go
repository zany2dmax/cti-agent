// Package useragent builds the User-Agent the fleet sends to the public sites
// it polls: vendor advisories, Microsoft's release API, the organisation's own
// websites.
//
// # WHY A CONTACT, AND WHY FROM fleet.env
//
// In November 2026 www.cisa.gov began answering every scout fetch with 403.
// The agent was a bare product token, `cti-agent-fleet/1.0`, which gives a
// site operator nothing to go on: no way to tell a security team's feed reader
// from a scraper, and nobody to ask. The courteous and conventional fix
// (RFC 9110 §10.1.5) is a contact in the agent, so a publisher who sees the
// traffic can write to us instead of blocking us.
//
// The contact is the fleet's own mailbox, GRAPH_MAILBOX, read at run time.
// This repository is public, so the address must not be written into it, and
// the mailbox the fleet already sends as is the right one to answer.
//
// The agent never pretends to be a browser. If a publisher blocks an honest
// agent, the answer is to ask them, not to disguise the request.
package useragent

import (
	"os"
	"regexp"
	"strings"
)

// mailbox is deliberately narrow: an address that could carry a ")" or a
// line break would let a fleet.env typo reshape the header.
var mailbox = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

// String returns the agent for one component. FLEET_USER_AGENT, when set,
// replaces product, the component's own token. The fleet's contact is then
// appended unless the agent already carries a comment, so an operator who
// wrote their own contact into FLEET_USER_AGENT keeps it unchanged.
func String(product string) string {
	return Build(product, os.Getenv("FLEET_USER_AGENT"), os.Getenv("GRAPH_MAILBOX"))
}

// Build is String without the environment, for tests.
func Build(product, override, contact string) string {
	ua := strings.TrimSpace(override)
	if ua == "" || strings.ContainsAny(ua, "\r\n") {
		ua = product
	}
	contact = strings.TrimSpace(contact)
	if strings.Contains(ua, "(") || !mailbox.MatchString(contact) {
		return ua
	}
	return ua + " (+mailto:" + contact + ")"
}
