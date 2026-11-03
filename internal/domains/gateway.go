package domains

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// WHAT THE MAIL GATEWAY KNOWS THAT DNS CANNOT
//
// DNS says what a domain is allowed to do; the gateway's log says what mail
// actually went out. A lock-down ticket asks IT to publish "v=spf1 -all" and
// DMARC p=reject for a domain the inventory says sends nothing. If that
// domain does send, the ticket breaks real mail. So when a gateway is
// configured, a domain with outbound mail in the window is never asked to be
// locked down, and the report says so loudly instead.
//
// THE RULE WHEN THE EVIDENCE IS MISSING
//
// If the gateway is configured and its read failed or was cut short, the run
// cannot prove a "sends nothing" domain really sends nothing. Then nothing is
// asked of IT: the lock-down records are held, the actions file is marked
// Held, and cti-jira files, comments and resolves nothing that run (an empty
// action list on an open ticket would otherwise be told "nothing is left to
// change"). The report still goes out and says why. A gateway that is not
// configured at all changes nothing: this is opt-in.
//
// The interface lives here and an implementation in a sub-package (podgw),
// the way the registrar does, so a second gateway can be added without
// touching the lane.

// MailGateway reads aggregate evidence of who really sends mail.
type MailGateway interface {
	// Name is for the report ("Proofpoint on Demand").
	Name() string
	// Evidence reads the window [since, to). Complete is false when the read
	// ended early; the returned counts then cover only part of the window and
	// must not be used to say a domain does NOT send.
	Evidence(ctx context.Context, since, to time.Time) (GatewayEvidence, error)
}

// InboundClaim counts inbound mail that carried a domain in its header From.
type InboundClaim struct {
	Total int
	Pass  int // DMARC passed
}

// GatewayEvidence is what one read found. Counts only: no address, subject or
// recipient is ever in it.
type GatewayEvidence struct {
	Gateway  string
	Since    time.Time
	To       time.Time
	Complete bool
	Reason   string // why it is not complete
	Events   int
	// Unattributed: outbound messages with no usable From domain (bounces and
	// unparsable names). Counted so the report can say they exist.
	Unattributed int
	Outbound     map[string]int          // header-From domain -> messages sent
	Inbound      map[string]InboundClaim // header-From domain -> inbound mail using it
}

// OutboundFor counts outbound mail whose header From is d or a subdomain.
func (e *GatewayEvidence) OutboundFor(d string) int {
	n := 0
	for k, v := range e.Outbound {
		if coveredBy(k, d) {
			n += v
		}
	}
	return n
}

// InboundFor sums the inbound claims on d and its subdomains.
func (e *GatewayEvidence) InboundFor(d string) InboundClaim {
	var c InboundClaim
	for k, v := range e.Inbound {
		if coveredBy(k, d) {
			c.Total += v.Total
			c.Pass += v.Pass
		}
	}
	return c
}

// GatewayStatus is what a run knows about its gateway check.
type GatewayStatus struct {
	Enabled  bool
	Evidence *GatewayEvidence
	Err      string
}

// OK reports whether the evidence can be used to say a domain does not send.
func (g *GatewayStatus) OK() bool {
	return g != nil && g.Enabled && g.Err == "" && g.Evidence != nil && g.Evidence.Complete
}

// Held reports that a gateway is configured but gave no usable evidence.
func (g *GatewayStatus) Held() bool { return g != nil && g.Enabled && !g.OK() }

// HeldWhy is the reason for the report and the log.
func (g *GatewayStatus) HeldWhy() string {
	switch {
	case g == nil || !g.Enabled:
		return ""
	case g.Err != "":
		return g.Err
	case g.Evidence == nil:
		return "no evidence was read"
	case !g.Evidence.Complete:
		if g.Evidence.Reason != "" {
			return g.Evidence.Reason
		}
		return "the read ended early"
	}
	return ""
}

// GatewayWindow is the read window: whole hours, ending more than an hour ago
// (the service serves archive data only for older hours) and at most 28 days
// long (it keeps 30).
func GatewayWindow(now time.Time, days int) (since, to time.Time) {
	if days < 1 {
		days = 7
	}
	if days > 28 {
		days = 28
	}
	to = now.Add(-time.Hour).Truncate(time.Hour)
	return to.Add(-time.Duration(days) * 24 * time.Hour), to
}

// gatewayNoise reports header-From values that are the gateway's own mail or
// a parse failure, not a domain of ours.
func gatewayNoise(d string) bool {
	switch d {
	case "", "(none)", "(unparsed)", "(other)", "localhost":
		return true
	}
	return strings.HasSuffix(d, ".onmicrosoft.com") || strings.HasSuffix(d, ".pphosted.com") ||
		strings.HasSuffix(d, ".outbound.protection.outlook.com")
}

const gatewayFinding = "(mail gateway)"

// EvalGateway turns the evidence into findings. A gateway that is not
// configured says nothing.
func EvalGateway(results []Result, gw *GatewayStatus) []Finding {
	if gw == nil || !gw.Enabled {
		return nil
	}
	var out []Finding
	add := func(d string, s Severity, f string, a ...any) {
		out = append(out, Finding{Domain: d, Sev: s, Area: "mail", Text: fmt.Sprintf(f, a...)})
	}
	if gw.Held() {
		add(gatewayFinding, Medium, "the mail gateway evidence is unavailable (%s): no lock-down change "+
			"is asked of IT this run and no Jira ticket is filed, changed or resolved. Fix the cause and "+
			"the next run catches up.", gw.HeldWhy())
		return out
	}
	ev := gw.Evidence
	days := int(ev.To.Sub(ev.Since).Hours() / 24)
	add(gatewayFinding, Info, "%s log, %s to %s UTC (%d days): %d events, outbound mail from %d header-From domain(s)"+
		"%s.", ev.Gateway, ev.Since.UTC().Format("2006-01-02 15:04"), ev.To.UTC().Format("2006-01-02 15:04"),
		days, ev.Events, countReal(ev.Outbound), unattributedNote(ev.Unattributed))

	inInventory := map[string]bool{}
	for _, r := range results {
		d := r.Entry.Name
		inInventory[d] = true
		p := ProfileOf(r.Entry)
		out2 := ev.OutboundFor(d)
		switch {
		case p.LockedDown() && out2 == 0 && ev.InboundFor(d).Pass > 0:
			add(d, High, "the inventory says this domain sends nothing, but %d inbound message(s) in %d days "+
				"used it in the From address and PASSED DMARC, so some service is authorised to send as it "+
				"(and may mail others directly). No lock-down change is asked of IT for it: find the service, "+
				"then correct the inventory (add \"send\" or \"saas\").", ev.InboundFor(d).Pass, days)
		case p.LockedDown() && out2 > 0:
			add(d, High, "the inventory says this domain sends nothing, but the gateway saw %d outbound "+
				"message(s) with it in the From address in %d days. No lock-down change is asked of IT "+
				"for it: find the sender, then correct the inventory (add \"send\") or stop the mail.",
				out2, days)
		case r.Entry.Sends && !r.Entry.SaaS && !r.Entry.Unknown && out2 == 0:
			add(d, Info, "marked as sending, but the gateway saw no outbound mail from it in %d days "+
				"(it may send some other way).", days)
		}
		if c := ev.InboundFor(d); c.Total > 0 {
			add(d, Info, "%d days of inbound mail used this domain in the From address: %d message(s), "+
				"%d passed DMARC, %d did not. Passing mail is our own cloud senders; the rest is what "+
				"p=reject would stop.", days, c.Total, c.Pass, c.Total-c.Pass)
		}
	}
	// Domains that send through the gateway but are not in the inventory.
	names := make([]string, 0, len(ev.Outbound))
	for k := range ev.Outbound {
		names = append(names, k)
	}
	sort.Strings(names)
	const maxUnknown = 10
	shown, more := 0, 0
	for _, k := range names {
		if gatewayNoise(k) {
			continue
		}
		known := false
		for d := range inInventory {
			if coveredBy(k, d) {
				known = true
				break
			}
		}
		if known {
			continue
		}
		// Forwarded and relayed mail keeps its original From, so this list can
		// name other people's domains: show the busiest few, say how many more.
		if shown >= maxUnknown {
			more++
			continue
		}
		shown++
		add(k, Medium, "%d outbound message(s) in %d days send as this domain through the gateway, "+
			"but it is not in the inventory.", ev.Outbound[k], days)
	}
	if more > 0 {
		add(gatewayFinding, Info, "%d more header-From domain(s) sent through the gateway and are not in the "+
			"inventory; only the first %d (alphabetically) are listed. The log holds the rest.", more, maxUnknown)
	}
	return out
}

func unattributedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; %d outbound message(s) had no usable From domain (bounces and similar) and are not attributed", n)
}

func countReal(m map[string]int) int {
	n := 0
	for k := range m {
		if !gatewayNoise(k) {
			n++
		}
	}
	return n
}
