package brief

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

var rule68 = strings.Repeat("-", 68)

// subjectsSection lists the email subjects the ingest read: "what did it
// actually look at?", with the ones that held a CVE marked.
func subjectsSection(data obj) string {
	subs := asList(or(data["email_subjects"], []any{}))
	if len(subs) == 0 {
		return ""
	}
	var rows strings.Builder
	for _, e := range firstN(subs, 60) {
		subj := strings.TrimSpace(str(or(get(e, "subject"), "(no subject)")))
		if subj == "" {
			subj = "(no subject)"
		}
		mark := "<span style='color:#a0aec0'>&mdash;</span>"
		if truthy(get(e, "has_cve")) {
			mark = "<span style='color:#b3001b;font-weight:700'>CVE</span>"
		}
		when := htmlEscape(strings.ReplaceAll(cut(sget(e, "received"), 16), "T", " "))
		rows.WriteString("<tr><td style=\"padding:3px 8px 3px 0;white-space:nowrap;" +
			"vertical-align:top\">" + mark + "</td>" +
			"<td style=\"padding:3px 8px 3px 0;white-space:nowrap;color:#718096;" +
			"vertical-align:top\">" + when + "</td>" +
			"<td style=\"padding:3px 0;color:#2d3748\">" + htmlEscape(subj) + "</td></tr>")
	}
	more := ""
	if len(subs) > 60 {
		more = fmt.Sprintf("<div style='color:#718096;margin-top:6px'>"+
			"+%d more in the attached raw report</div>", len(subs)-60)
	}
	nCVE := 0
	for _, e := range subs {
		if truthy(get(e, "has_cve")) {
			nCVE++
		}
	}
	return fmt.Sprintf(`
  <tr><td style="padding:4px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin:12px 0 8px 0;letter-spacing:.5px">
      EMAILS READ THIS RUN &mdash; %d total, %d mentioning a CVE</div>
    <table cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
      %s
    </table>%s
  </td></tr>`, len(subs), nCVE, rows.String(), more)
}

// fleetTickets splits the ticket map into open and recently closed, each
// sorted by key: every fleet ticket cti-jira found this run, not only those
// whose CVE is in today's mail. Supplier requests are one summary line.
func fleetTickets(data obj) (open, closed []obj) {
	keys := make([]string, 0, len(asObj(data["_tickets"])))
	for k := range asObj(data["_tickets"]) {
		keys = append(keys, k)
	}
	sort.Strings(keys) // a decoded map has no order; ties below are by key anyway
	for _, cve := range keys {
		t, ok := asObj(data["_tickets"])[cve].(obj)
		if !ok || !truthy(t["key"]) || str(t["kind"]) == "supplier-request" && t["kind"] != nil {
			continue
		}
		row := obj{}
		for k, v := range t {
			row[k] = v
		}
		row["cve"] = or(t["cve"], cve)
		if truthy(t["done"]) {
			closed = append(closed, row)
		} else {
			open = append(open, row)
		}
	}
	less := func(a, b obj) bool {
		ka, kb := str(a["key"]), str(b["key"])
		pa, na := splitKey(ka)
		pb, nb := splitKey(kb)
		if pa != pb {
			return pa < pb
		}
		if c := numPart(na).Cmp(numPart(nb)); c != 0 {
			return c < 0
		}
		return ka < kb
	}
	sort.SliceStable(open, func(i, j int) bool { return less(open[i], open[j]) })
	sort.SliceStable(closed, func(i, j int) bool { return less(closed[i], closed[j]) })
	return open, closed
}

// splitKey is k.rpartition("-"): ("", k) when there is no dash.
func splitKey(k string) (string, string) {
	i := strings.LastIndex(k, "-")
	if i < 0 {
		return "", k
	}
	return k[:i], k[i+1:]
}

// numPart is int(num) if num.isdigit() else 0, as a number of any size.
func numPart(s string) *big.Int {
	if isDigits(s) {
		return digitsKey(s)
	}
	return new(big.Int)
}

func supplierLine(data obj) string {
	n := 0
	for _, t := range asObj(data["_tickets"]) {
		if o, ok := t.(obj); ok && str(o["kind"]) == "supplier-request" && o["kind"] != nil && !truthy(o["done"]) {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d Supplier request ticket%s opened for TPRM evaluation", n, pluralN(n))
}

func ticketHosts(t obj) string {
	switch k, _ := t["kind"].(string); k {
	case "domains-lockdown":
		return "DNS changes for IT"
	case "vmscan-sheet-fixes":
		return "spreadsheet fixes for the network team"
	case "fleet-other":
		return "listed, not re-checked"
	}
	if !truthy(t["checked"]) {
		return "not re-checked"
	}
	n := or(t["hosts"], json0)
	if isZero(n) {
		return "no hosts"
	}
	return str(n) + " host" + plural(n)
}

// ticketsHeading is what the FLEET TICKETS heading may claim: the daily's
// map was re-checked this morning, the weekly borrows the daily's, and a
// map listed without the scanner was not re-checked at all.
func ticketsHeading(data obj, nOpen int) string {
	if truthy(data["_tickets_listed_only"]) {
		return fmt.Sprintf("%d open, listed from Jira - not re-checked against the scanner this run", nOpen)
	}
	if str(data["_kind"]) == "weekly" && data["_kind"] != nil {
		return fmt.Sprintf("%d open, as the latest daily re-checked them against the scanner", nOpen)
	}
	return fmt.Sprintf("%d open, re-checked against the scanner today", nOpen)
}

func fleetTicketsSection(data obj) string {
	open, closed := fleetTickets(data)
	sup := supplierLine(data)
	if len(open) == 0 && len(closed) == 0 && sup == "" {
		return ""
	}
	products := productsByCVE(data)
	row := func(t obj) string {
		// Only a CVE ticket has a product; the lane tickets have a kind.
		product := ""
		if !truthy(t["kind"]) {
			if p := products[str(or(t["cve"], ""))]; truthy(p) {
				product = `<span style="background:#fff4c2;color:#1a202c;padding:0 4px;` +
					`border-radius:3px;font-weight:700">` + esc(p) + `</span> &middot; `
			}
		}
		key := esc(t["key"])
		url := str(or(t["url"], ""))
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			key = `<a href="` + htmlEscape(url) + `" style="color:` + emailkit.Navy + `;font-weight:700">` + key + `</a>`
		} else {
			key = "<b>" + key + "</b>"
		}
		status := esc(or(t["status"], ""))
		outcome := esc(or(t["outcome"], ""))
		if outcome != "" {
			outcome = `<br><span style="color:#718096">` + outcome + `</span>`
		}
		return "<tr><td style=\"padding:5px 8px 5px 0;vertical-align:top;white-space:nowrap\">" +
			key + "</td>" +
			"<td style=\"padding:5px 8px 5px 0;vertical-align:top;white-space:nowrap;" +
			"color:#4a5568\">" + esc(or(t["cve"], "")) + "<br>" + status + "</td>" +
			"<td style=\"padding:5px 0;vertical-align:top;color:#2d3748\">" +
			product + "<b>" + htmlEscape(ticketHosts(t)) + "</b>" + outcome + "</td></tr>"
	}
	var parts strings.Builder
	for _, t := range open {
		parts.WriteString(row(t))
	}
	if sup != "" {
		parts.WriteString("<tr><td colspan=\"3\" style=\"padding:6px 0;color:#2d3748\">" +
			"<b>" + htmlEscape(sup) + "</b></td></tr>")
	}
	if len(closed) > 0 {
		parts.WriteString("<tr><td colspan=\"3\" style=\"padding:10px 0 2px 0;color:#718096;" +
			"font-weight:700\">Closed in the last 30 days</td></tr>")
		for _, t := range closed {
			parts.WriteString(row(t))
		}
	}
	return `
  <tr><td style="padding:4px 20px 14px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin:12px 0 8px 0;letter-spacing:.5px">
      FLEET TICKETS &mdash; ` + htmlEscape(ticketsHeading(data, len(open))) + `</div>
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
      ` + parts.String() + `
    </table>
  </td></tr>`
}

func fleetTicketsText(data obj) []string {
	open, closed := fleetTickets(data)
	sup := supplierLine(data)
	if len(open) == 0 && len(closed) == 0 && sup == "" {
		return nil
	}
	lines := []string{"FLEET TICKETS - " + ticketsHeading(data, len(open)), rule68}
	products := productsByCVE(data)
	add := func(t obj) {
		lines = append(lines, "  "+padRight(str(t["key"]), 10)+" "+padRight(str(or(t["cve"], "")), 16)+" "+
			padRight(str(or(t["status"], "")), 14)+" "+ticketHosts(t))
		if !truthy(t["kind"]) {
			if p := products[str(or(t["cve"], ""))]; truthy(p) {
				lines = append(lines, "    Product: "+str(p))
			}
		}
		if truthy(t["outcome"]) {
			lines = append(lines, "    "+str(t["outcome"]))
		}
		if truthy(t["url"]) {
			lines = append(lines, "    "+str(t["url"]))
		}
	}
	for _, t := range open {
		add(t)
	}
	if sup != "" {
		lines = append(lines, "  "+sup)
	}
	if len(closed) > 0 {
		lines = append(lines, "  Closed in the last 30 days:")
		for _, t := range closed {
			add(t)
		}
	}
	return append(lines, "")
}

func approveCommand(data obj) string {
	return "sudo cti-agent cti-jira --from-enriched " + str(or(data["_enriched"], "<file>")) + " --for-real --approve"
}

func heldHosts(h any) string {
	n := or(get(h, "hosts"), json0)
	return str(n) + " host" + plural(n)
}

// heldSection is HELD FOR APPROVAL: qualifying CVEs the scheduled run did
// not file, so the reader can tell a ticket not filed from one not wanted.
func heldSection(data obj) string {
	held := asList(or(data["_held"], []any{}))
	if len(held) == 0 {
		return ""
	}
	products := productsByCVE(data)
	var rows strings.Builder
	for _, h := range held {
		prod := ""
		if p := products[str(get(h, "cve"))]; truthy(p) {
			prod = "<br><b>" + esc(p) + "</b>"
		}
		rows.WriteString("<tr><td style=\"padding:3px 12px 3px 0;white-space:nowrap;vertical-align:top\">" +
			"<b>" + esc(get(h, "cve")) + "</b>" + prod + "</td>" +
			"<td style=\"padding:3px 12px 3px 0;white-space:nowrap\">" +
			htmlEscape(heldHosts(h)) + "</td>" +
			"<td style=\"padding:3px 0;color:#4a5568\">" + esc(or(get(h, "title"), "")) + "</td></tr>")
	}
	return fmt.Sprintf(`
  <tr><td style="padding:4px 20px 14px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#9c4221;margin:12px 0 6px 0;letter-spacing:.5px">
      HELD FOR APPROVAL &mdash; %d Sev5 with no ticket</div>
    <div style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#2d3748;margin-bottom:6px">
      Confirmed present and known exploited, but not on CISA KEV, not CVSS 9.0+
      and not QDS 91+, so the scheduled run does not file it. No ticket exists for these.</div>
    <table cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
      %s
    </table>
    <div style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#2d3748;margin-top:6px">
      To file them: <code>%s</code></div>
  </td></tr>`, len(held), rows.String(), htmlEscape(approveCommand(data)))
}

func heldText(data obj) []string {
	held := asList(or(data["_held"], []any{}))
	if len(held) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("HELD FOR APPROVAL - %d Sev5 with no ticket", len(held)), rule68,
		"  Confirmed present and known exploited, but not on CISA KEV, not",
		"  CVSS 9.0+ and not QDS 91+, so the scheduled run does not file it."}
	products := productsByCVE(data)
	for _, h := range held {
		title := ""
		if truthy(get(h, "title")) {
			title = "  " + str(get(h, "title"))
		}
		prod := ""
		if p := products[str(get(h, "cve"))]; truthy(p) {
			prod = "  [" + str(p) + "]"
		}
		lines = append(lines, "  "+padRight(str(get(h, "cve")), 16)+" "+heldHosts(h)+prod+title)
	}
	return append(lines, "  To file them:", "    "+approveCommand(data), "")
}

// ── FLEET ADVISORIES ────────────────────────────────────────────────────────
//
// Advisory triage (cti-triage --batch, TRIAGE_ENABLED). Everything here came
// from mail anyone can send, so nothing is a link - subjects, senders,
// indicators and product names are escaped text - and a sighting is printed
// first whatever the judge said. Every advisory read is listed.

const (
	advHeading = "FLEET ADVISORIES"
	advNote    = "Judged from what our own tools hold. Never a statement that we are " +
		"or are not affected - check before acting."
)

var advRank = map[string]int{"likely": 0, "possible": 1, "unknown": 2, "unlikely": 3}

type advResult struct {
	seen, best int
	r          obj
	verdicts   []obj
	sightings  []obj
}

func objs(l []any) []obj {
	var out []obj
	for _, x := range l {
		if o, ok := x.(obj); ok {
			out = append(out, o)
		}
	}
	return out
}

// advResults is the results in reading order: sightings first, then the
// best relevance.
func advResults(rep obj) []advResult {
	var out []advResult
	for _, x := range asList(or(rep["results"], []any{})) {
		r, ok := x.(obj)
		if !ok || truthy(r["not_threat_intel"]) {
			continue
		}
		v := asObj(r["verdicts"])
		verdicts := objs(asList(or(v["verdicts"], []any{})))
		sightings := objs(asList(or(v["sightings"], []any{})))
		best := 4
		for i, x := range verdicts {
			rank := 2
			if s, ok := x["relevance"].(string); ok {
				if n, ok := advRank[s]; ok {
					rank = n
				}
			}
			if i == 0 || rank < best {
				best = rank
			}
		}
		if truthy(r["not_triaged"]) {
			best = 5
		}
		seen := 1
		if len(sightings) > 0 {
			seen = 0
		}
		out = append(out, advResult{seen, best, r, verdicts, sightings})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].seen != out[j].seen {
			return out[i].seen < out[j].seen
		}
		return out[i].best < out[j].best
	})
	return out
}

func advNotIntel(rep obj) []string {
	var out []string
	for _, x := range asList(or(rep["results"], []any{})) {
		if r, ok := x.(obj); ok && truthy(r["not_threat_intel"]) {
			out = append(out, str(or(r["subject"], "(no subject)")))
		}
	}
	return out
}

func advSummary(rep obj) string {
	read := pyInt(or(rep["read"], json0))
	worth := 0
	for _, a := range advResults(rep) {
		if a.seen == 0 || a.best <= 1 {
			worth++
		}
	}
	return fmt.Sprintf("%d threat-intel message%s, %d worth a look", read, pluralN(read), worth)
}

func advName(x obj) string {
	name := str(or(or(x["title"], x["subject"]), ""))
	if truthy(x["name"]) {
		name += " (" + str(x["name"]) + ")"
	}
	return name
}

func advSender(r obj) string {
	who := str(or(r["sender"], "unknown sender"))
	if truthy(r["trusted_sender"]) {
		return who + " (a listed threat-intel sender)"
	}
	if why := str(or(r["why"], "")); why != "" {
		return who + " - picked for " + why
	}
	return who
}

func strs(l []any) []string {
	out := make([]string, len(l))
	for i, x := range l {
		out[i] = str(x)
	}
	return out
}

func moreN(n, over int) string {
	if n > over {
		return fmt.Sprintf(" (+%d more)", n-over)
	}
	return ""
}

func firstS(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// advRowHTML is one advisory's row; when, if set, is the day it arrived
// (the weekly's roll-up).
func advRowHTML(a advResult, when string) string {
	red := emailkit.Red
	r := a.r
	parts := []string{`<b>` + esc(or(r["subject"], "(no subject)")) + `</b>` +
		`<br><span style="color:#718096">` + advWhen(when) + `from ` + htmlEscape(advSender(r)) + `</span>`}
	for _, x := range a.sightings {
		parts = append(parts,
			`<div style="background:`+red.Bg+`;color:`+red.Fg+`;border-left:3px solid `+red.Fg+`;`+
				`padding:4px 8px;margin:4px 0;font-weight:700">SEEN ON OUR HOSTS: `+
				esc(x["value"])+` (`+esc(x["type"])+`) on `+esc(x["hosts_seen_on"])+` `+
				`host(s). Treat it as an incident lead.</div>`)
	}
	if truthy(r["not_triaged"]) {
		parts = append(parts, `<div style="color:#718096">Not triaged: `+esc(r["not_triaged"])+`</div>`)
	}
	if items := strs(asList(or(r["cve_items"], []any{}))); len(items) > 0 {
		parts = append(parts, `<div style="color:#718096">In the CVE report above, not judged here: `+
			htmlEscape(strings.Join(firstS(items, 6), "; "))+htmlEscape(moreN(len(items), 6))+`</div>`)
	}
	for _, x := range a.verdicts {
		rel := str(or(x["relevance"], "unknown"))
		label := `<b>` + htmlEscape(strings.ToUpper(rel)) + `</b> &middot; ` + htmlEscape(advName(x))
		if rel == "likely" || rel == "possible" {
			by := ""
			if str(x["reason_by"]) == "code" && x["reason_by"] != nil {
				by = " (code)"
			}
			detail := []string{esc(x["reason"]) + by}
			if truthy(x["raised_by_code"]) {
				detail = append(detail, "Raised by code: "+esc(x["raised_by_code"]))
			}
			for _, fct := range firstN(asList(or(x["facts"], []any{})), 6) {
				if fo, ok := fct.(obj); ok {
					detail = append(detail, "Fact: "+esc(fo["text"]))
				}
			}
			for _, c := range firstN(asList(or(x["suggested_checks"], []any{})), 3) {
				detail = append(detail, "Check: "+esc(c))
			}
			parts = append(parts, `<div style="margin-top:4px">`+label+`<br>`+
				`<span style="color:#2d3748">`+strings.Join(detail, "<br>")+`</span></div>`)
		} else {
			parts = append(parts, `<div style="margin-top:2px;color:#4a5568">`+label+`</div>`)
		}
	}
	for _, pr := range firstN(asList(or(r["problems"], []any{})), 3) {
		parts = append(parts, `<div style="color:#718096">Note: `+esc(pr)+`</div>`)
	}
	return `<tr><td style="padding:6px 0;vertical-align:top;` +
		`border-bottom:1px solid #edf2f7">` + strings.Join(parts, "") + `</td></tr>`
}

func advWhen(when string) string {
	if when == "" {
		return ""
	}
	return htmlEscape(when) + " &middot; "
}

func advisoriesSection(data obj) string {
	// Only the weekly's Prepare reads the week's reports.
	if _, ok := data["_advisories_week"].(advWeekData); ok && str(data["_kind"]) == "weekly" {
		return advWeekSection(data)
	}
	if str(data["_kind"]) != "daily" || data["_kind"] == nil {
		return ""
	}
	var body, summary string
	rep, ok := data["_advisories"].(obj)
	if data["_advisories"] == nil || !ok {
		if !truthy(data["_triage_enabled"]) {
			return ""
		}
		body = `<tr><td style="padding:4px 0;color:#4a5568">Advisory triage is on but ` +
			`reported nothing today: no threat-intel mail arrived, or it failed. ` +
			`The digest run log says which.</td></tr>`
		summary = "no report"
	} else {
		var rows strings.Builder
		for _, a := range advResults(rep) {
			rows.WriteString(advRowHTML(a, ""))
		}
		if quiet := advNotIntel(rep); len(quiet) > 0 {
			rows.WriteString(`<tr><td style="padding:4px 0;color:#718096">Read, no threat found: ` +
				htmlEscape(strings.Join(firstS(quiet, 8), "; ")) + htmlEscape(moreN(len(quiet), 8)) + `</td></tr>`)
		}
		if truthy(rep["over_ingest_cap"]) {
			rows.WriteString(`<tr><td style="padding:4px 0;color:#718096">+` + esc(rep["over_ingest_cap"]) + ` ` +
				`more not saved for triage (over the ingest cap).</td></tr>`)
		}
		gaps := join(asList(or(rep["gaps"], []any{})), "; ")
		foot := htmlEscape(advNote)
		if gaps != "" {
			foot += "<br>Not covered: " + htmlEscape(gaps) + "."
		}
		foot += fmt.Sprintf("<br>Model cost: $%.2f.", pyFloat(or(rep["cost_usd"], json0)))
		rows.WriteString(`<tr><td style="padding:6px 0;color:#718096;font-size:11px">` + foot + `</td></tr>`)
		body = rows.String()
		summary = advSummary(rep)
	}
	return `
  <tr><td style="padding:4px 20px 14px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin:12px 0 8px 0;letter-spacing:.5px">
      ` + advHeading + ` &mdash; ` + htmlEscape(summary) + `</div>
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
      ` + body + `
    </table>
  </td></tr>`
}

// advRowText is advRowHTML for the text part.
func advRowText(a advResult, when string) []string {
	var lines []string
	r := a.r
	lines = append(lines, "  "+str(or(r["subject"], "(no subject)")), "    "+advWhenText(when)+"from "+advSender(r))
	for _, x := range a.sightings {
		lines = append(lines, "    >>> SEEN ON OUR HOSTS: "+str(x["value"])+" ("+str(x["type"])+") on "+
			str(x["hosts_seen_on"])+" host(s). Treat it as an incident lead.")
	}
	if truthy(r["not_triaged"]) {
		lines = append(lines, "    Not triaged: "+str(r["not_triaged"]))
	}
	if items := strs(asList(or(r["cve_items"], []any{}))); len(items) > 0 {
		lines = append(lines, "    In the CVE report above, not judged here: "+
			strings.Join(firstS(items, 6), "; ")+moreN(len(items), 6))
	}
	for _, x := range a.verdicts {
		rel := str(or(x["relevance"], "unknown"))
		lines = append(lines, "    "+strings.ToUpper(rel)+"  "+advName(x))
		if rel == "likely" || rel == "possible" {
			by := ""
			if str(x["reason_by"]) == "code" && x["reason_by"] != nil {
				by = " (code)"
			}
			lines = append(lines, "      "+str(x["reason"])+by)
			if truthy(x["raised_by_code"]) {
				lines = append(lines, "      Raised by code: "+str(x["raised_by_code"]))
			}
			for _, fct := range firstN(asList(or(x["facts"], []any{})), 6) {
				if fo, ok := fct.(obj); ok {
					lines = append(lines, "      Fact: "+str(fo["text"]))
				}
			}
			for _, c := range firstN(asList(or(x["suggested_checks"], []any{})), 3) {
				lines = append(lines, "      Check: "+str(c))
			}
		}
	}
	for _, pr := range firstN(asList(or(r["problems"], []any{})), 3) {
		lines = append(lines, "    Note: "+str(pr))
	}
	return lines
}

func advWhenText(when string) string {
	if when == "" {
		return ""
	}
	return when + " - "
}

func advisoriesText(data obj) []string {
	// Only the weekly's Prepare reads the week's reports.
	if _, ok := data["_advisories_week"].(advWeekData); ok && str(data["_kind"]) == "weekly" {
		return advWeekText(data)
	}
	if str(data["_kind"]) != "daily" || data["_kind"] == nil {
		return nil
	}
	rep, ok := data["_advisories"].(obj)
	if data["_advisories"] == nil || !ok {
		if !truthy(data["_triage_enabled"]) {
			return nil
		}
		return []string{advHeading + " - no report", rule68,
			"  Advisory triage is on but reported nothing today: no threat-intel",
			"  mail arrived, or it failed. The digest run log says which.", ""}
	}
	lines := []string{advHeading + " - " + advSummary(rep), rule68}
	for _, a := range advResults(rep) {
		lines = append(lines, advRowText(a, "")...)
	}
	if quiet := advNotIntel(rep); len(quiet) > 0 {
		lines = append(lines, "  Read, no threat found: "+strings.Join(firstS(quiet, 8), "; ")+moreN(len(quiet), 8))
	}
	if truthy(rep["over_ingest_cap"]) {
		lines = append(lines, "  +"+str(rep["over_ingest_cap"])+" more not saved for triage (over the ingest cap).")
	}
	lines = append(lines, "  "+advNote)
	if gaps := join(asList(or(rep["gaps"], []any{})), "; "); gaps != "" {
		lines = append(lines, "  Not covered: "+gaps+".")
	}
	lines = append(lines, fmt.Sprintf("  Model cost: $%.2f.", pyFloat(or(rep["cost_usd"], json0))), "")
	return lines
}
