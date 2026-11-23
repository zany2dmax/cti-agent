// Package brief renders the enriched findings as the daily and weekly
// digest email: HTML for the mail client, plain text for the alternative and
// the log, and the subject line.
//
// Built for a phone screen at 6am: Sev5 first, host counts visible, action
// stated. Inline CSS and a table layout because Outlook ignores most of
// everything else.
//
// It replaced the Python brief.py lane and writes the same email, byte for
// byte: the golden files in testdata were written by that Python, and the
// tests hold this package to them. The data is the decoded JSON as it comes
// (the enriched file, or fleet-db's rollup), read with the Python's rules
// for missing and null values (see py.go).
package brief

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
	"github.com/zany2dmax/cti-agent/internal/pyfmt"
)

// SevOrder is the bands, most urgent first.
//
// Deliberately NOT P1-P4: that is the incident-reporting scale here, and a
// CTI digest labelled "P1" reads as a live incident to anyone on the rota.
var SevOrder = []string{"Sev5", "Sev4", "Sev3", "Sev2", "Sev1"}

type band struct{ fg, bg, label string }

// pri is each band's colours and heading. Five bands so that every label is
// true on its own: none claims presence the scanner did not establish.
var pri = map[string]band{
	"Sev5": {emailkit.Red.Fg, emailkit.Red.Bg, "Exploited AND confirmed present - act today"},
	"Sev4": {emailkit.Amber.Fg, emailkit.Amber.Bg, "Confirmed present, not known to be exploited - this patch cycle"},
	"Sev3": {emailkit.Yellow.Fg, emailkit.Yellow.Bg, "Exploited, coverage UNVERIFIED - we cannot say whether we are exposed"},
	"Sev2": {emailkit.Blue.Fg, emailkit.Blue.Bg, "Exploited but not detected here, or unverified critical - verify coverage"},
	"Sev1": {emailkit.Grey.Fg, emailkit.Grey.Bg, "Awareness only"},
}

// RowLimits is how many rows of each band the digest lists. 0 means no
// section: the band's number is still in the tiles and the text header,
// which is all an awareness item warrants. Sev5 is deliberately uncapped.
// Both renderers read this one table.
var RowLimits = map[string]map[string]int{
	"daily":  {"Sev5": 99, "Sev4": 12, "Sev3": 12, "Sev2": 10, "Sev1": 0},
	"weekly": {"Sev5": 99, "Sev4": 15, "Sev3": 15, "Sev2": 12, "Sev1": 0},
}

// A CVE a colleague mailed in to be checked is listed whatever its band, in
// its own section above the bands.
const (
	askedLimit   = 25
	askedHeading = "Asked about - CVEs the team mailed in to be checked"
	askedNote    = "Sent to the mailbox by a colleague. Each was looked up against " +
		"the scanner, and is listed here whatever its severity; a " +
		"status of UNKNOWN means the scanner has no mapping for it yet, " +
		"not that we are clean."
)

var mixedNote = map[string]string{
	"Sev3": "These are being actively exploited and the scanner has no QID " +
		"mapping for them, so it could not tell us whether we are exposed. " +
		"That is not a confirmed exposure and it is not a clean result " +
		"&mdash; it means nobody looked. Below Sev4 because a gap may " +
		"turn out to be nothing, but well above the awareness floor, " +
		"because it may equally turn out to be everything.",
	"Sev2": "<b>NOT_PRESENT</b> rows were checked and the scanner found " +
		"nothing. <b>UNKNOWN</b> rows were not checked. Both warrant a " +
		"look at scan coverage rather than a patch.",
}

func asked(findings []any) []any {
	var out []any
	for _, f := range findings {
		if v, ok := get(f, "asked").(bool); ok && v {
			out = append(out, f)
		}
	}
	return out
}

// bandNeedsCaveat is true when a band holds an unverified row: a caveat
// printed every day stops being read on the day it matters.
func bandNeedsCaveat(group []any) bool {
	for _, f := range group {
		if str(or(get(f, "status"), "UNKNOWN")) == "UNKNOWN" {
			return true
		}
	}
	return false
}

var linkRE = regexp.MustCompile(`(?i)^(https?)://([^\s/?#]+)`)

// safeLinkURL is raw only when it is safe in an href (http or https), else
// "". The Go lanes apply the same rule (internal/safelink).
func safeLinkURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if linkRE.MatchString(raw) {
		return raw
	}
	return ""
}

// Env is what the renderer reads from the environment, and where it warns.
type Env struct {
	Org         string // FLEET_ORG, "Security" when unset
	Attribution string // FLEET_ATTRIBUTION
	RepoURL     string // FLEET_REPO_URL
	Warn        func(string)
}

// EnvFromOS reads the renderer's settings.
func EnvFromOS() Env {
	org, ok := os.LookupEnv("FLEET_ORG")
	if !ok {
		org = "Security"
	}
	return Env{Org: org, Attribution: os.Getenv("FLEET_ATTRIBUTION"), RepoURL: os.Getenv("FLEET_REPO_URL"),
		Warn: func(s string) { fmt.Fprintln(os.Stderr, s) }}
}

// attribution is the credit line: configured, never hardcoded. ("", "")
// renders nothing, so a fresh install advertises nobody. The default text is
// used only when a URL was given.
func (e Env) attribution() (string, string) {
	text := strings.TrimSpace(e.Attribution)
	raw := strings.TrimSpace(e.RepoURL)
	url := safeLinkURL(raw)
	if raw != "" && url == "" && e.Warn != nil {
		e.Warn("[brief] ignoring FLEET_REPO_URL=" + pyfmt.ReprString(raw) +
			" - only http:// and https:// are rendered as links")
	}
	if text == "" && url == "" {
		return "", ""
	}
	if text == "" {
		text = "Correlated and published by the " + e.Org + " Claude Code Agent Fleet"
	}
	return text, url
}

// Subject is the subject line. Sev5 leads; an overdue KEV deadline rides
// along rather than displacing it; otherwise it counts what the scanner
// confirmed, never the size of a band.
func Subject(data obj, kind string, now time.Time) string {
	c := asObj(data["counts"])
	day := now.Format("Jan 02")
	label, window := "CTI "+day, "the last 24h"
	if kind == "weekly" {
		label, window = "CTI Weekly "+day, "the last 7 days"
	}
	kev := or(data["kev_deadlines"], obj{})
	overdue := or(get(kev, "overdue"), json0)
	tail := ""
	if truthy(overdue) {
		tail = fmt.Sprintf(" — %s KEV deadline%s OVERDUE", str(overdue), plural(overdue))
	}
	if truthy(c["Sev5"]) {
		return fmt.Sprintf("[Sev5] %s: %s exploited vuln%s present in the environment%s",
			label, str(c["Sev5"]), plural(c["Sev5"]), tail)
	}
	if truthy(overdue) {
		return fmt.Sprintf("[OVERDUE] %s: %s CISA KEV deadline%s passed, worst by %sd",
			label, str(overdue), plural(overdue), str(getOr(kev, "worst_overdue_days", json0)))
	}
	present, unverified := counts(asList(or(data["findings"], []any{})))
	if present > 0 {
		s := fmt.Sprintf("%s: %d confirmed present, no Sev5", label, present)
		if unverified > 0 {
			s += fmt.Sprintf(", %d unverified", unverified)
		}
		return s
	}
	if unverified > 0 {
		return fmt.Sprintf("%s: 0 confirmed present, %d exploited CVE%s the scanner could not check",
			label, unverified, pluralN(unverified))
	}
	if isZero(data["total"]) {
		return fmt.Sprintf("%s: no new CVEs in %s", label, window)
	}
	return fmt.Sprintf("%s: %s CVEs reviewed, nothing exploitable found", label, str(data["total"]))
}

// json0 is the 0 a missing count defaults to.
var json0 = json.Number("0")

// isZero is `v == 0` in Python: a number (or False) equal to zero.
func isZero(v any) bool {
	switch v.(type) {
	case json.Number, bool, int, float64:
		return num(v) == 0
	}
	return false
}

func pluralN(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// counts is (confirmed present, unverified exploited) over the findings.
func counts(rows []any) (present, unverified int) {
	for _, f := range rows {
		st, _ := get(f, "status").(string)
		if st == "PRESENT" && num(or(get(f, "host_count"), json0)) > 0 {
			present++
		}
		if p, _ := get(f, "priority").(string); st == "UNKNOWN" && (p == "Sev3" || p == "Sev2") {
			unverified++
		}
	}
	return present, unverified
}

var pseudoRE = regexp.MustCompile(`^host-[0-9a-f]{8}$`)

func hostsCell(f any) string {
	var hosts []string
	for _, h := range strings.Split(sget(f, "sample_hosts"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return "&mdash;"
	}
	// A pseudonym is not a hostname and cannot be looked up anywhere.
	pseudo := true
	for _, h := range hosts {
		if !pseudoRE.MatchString(h) {
			pseudo = false
		}
	}
	// Dedupe but keep order: the raw report repeats hosts across QIDs.
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		if k := strings.ToLower(h); !seen[k] {
			seen[k] = true
			out = append(out, h)
		}
	}
	shown := make([]string, 0, 6)
	for i, h := range out {
		if i == 6 {
			break
		}
		shown = append(shown, htmlEscape(h))
	}
	s := strings.Join(shown, ", ")
	if len(out) > 6 {
		s += fmt.Sprintf(" <span style='color:#718096'>+%d more</span>", len(out)-6)
	}
	if pseudo {
		s += "  <span style='color:#b25000'>(pseudonymized &mdash; set " +
			"REPORT_HOSTNAMES=full for real names)</span>"
	}
	return s
}

func providerReasonCell(f any) string {
	reason := strings.TrimSpace(sget(f, "provider_reason"))
	if reason == "" {
		return ""
	}
	return "<div style=\"font:400 12px/1.5 -apple-system,Segoe UI,Helvetica," +
		"Arial,sans-serif;color:#744210;background:#fffbe6;padding:6px 8px;" +
		"border-radius:3px;margin-top:6px\"><b>Scanner:</b> " + htmlEscape(reason) + "</div>"
}

// qidsCell is the scanner's own IDs: a finding cannot be looked up in
// Qualys by CVE, only by QID. A long list is cut; the count is always shown.
func qidsCell(f any) string {
	raw := strings.TrimSpace(sget(f, "qids"))
	if raw == "" {
		return ""
	}
	var qids []string
	for _, q := range strings.Split(raw, ",") {
		if q = strings.TrimSpace(q); q != "" {
			qids = append(qids, q)
		}
	}
	if len(qids) == 0 {
		return ""
	}
	shown := make([]string, 0, 8)
	for i, q := range qids {
		if i == 8 {
			break
		}
		shown = append(shown, htmlEscape(q))
	}
	extra := ""
	if len(qids) > 8 {
		extra = fmt.Sprintf(" <span style='color:#718096'>+%d more</span>", len(qids)-8)
	}
	label := "QID"
	if len(qids) != 1 {
		label = fmt.Sprintf("QIDs (%d)", len(qids))
	}
	return "<div style=\"font:400 12px/1.5 -apple-system,Segoe UI,Helvetica," +
		"Arial,sans-serif;color:#4a5568;margin-top:4px\">" +
		"<b>" + label + ":</b> <span style='font-family:ui-monospace,SFMono-Regular," +
		"Menlo,monospace'>" + strings.Join(shown, ", ") + "</span>" + extra + "</div>"
}

// productLabel is what a finding is about, as cti-enrich named it. ok is
// false when the finding predates the field (an old rollup row), so the card
// renders as it always did; "" means enrich looked and found nothing.
func productLabel(f any) (string, bool) {
	if !has(f, "product") {
		return "", false
	}
	return strings.Join(strings.Fields(sget(f, "product")), " "), true
}

func productHTML(f any) string {
	p, ok := productLabel(f)
	if !ok {
		return ""
	}
	if p == "" {
		return `<span style="color:#718096;font-weight:400;font-size:12px">` +
			`&middot; product not identified</span>`
	}
	title := ""
	if src := or(get(f, "product_source"), ""); truthy(src) {
		title = ` title="from ` + esc(src) + `"`
	}
	return `<span` + title + ` style="background:#fff4c2;color:#1a202c;padding:1px 6px;` +
		`border-radius:3px;font-weight:700">` + htmlEscape(p) + `</span>`
}

// productsByCVE is cve -> product, for rows that are not today's findings:
// today's findings win, the product map beside the enriched file fills in
// the rest.
func productsByCVE(data obj) obj {
	out := obj{}
	for k, v := range asObj(data["_products"]) {
		out[k] = v
	}
	for _, f := range asList(data["findings"]) {
		if truthy(get(f, "product")) {
			out[str(get(f, "cve"))] = get(f, "product")
		}
	}
	return out
}

func ticketCellHTML(f any, tickets obj) string {
	t := tickets[str(or(get(f, "cve"), ""))]
	if !truthy(t) || !truthy(get(t, "key")) {
		return ""
	}
	key := esc(get(t, "key"))
	url := str(or(get(t, "url"), ""))
	label := key
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		label = `<a href="` + htmlEscape(url) + `" style="color:` + emailkit.Navy + `">` + key + `</a>`
	}
	status := ""
	if truthy(get(t, "status")) {
		status = " &middot; " + esc(get(t, "status"))
	}
	return `<div style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,` +
		`Arial,sans-serif;color:#4a5568;margin-top:4px">` +
		`<b>Ticket:</b> ` + label + status + `</div>`
}

func ticketCellText(f any, tickets obj) (string, bool) {
	t := tickets[str(or(get(f, "cve"), ""))]
	if !truthy(t) || !truthy(get(t, "key")) {
		return "", false
	}
	status := ""
	if truthy(get(t, "status")) {
		status = " (" + str(get(t, "status")) + ")"
	}
	return strings.TrimRight("    Ticket: "+str(get(t, "key"))+status+"  "+sget(t, "url"), " \t\n\r\v\f"), true
}

func badge(style, text string) string {
	return "<span style='" + style + "'>" + text + "</span>"
}

const badgeBold = "padding:2px 6px;border-radius:3px;font-size:11px;font-weight:700"

func findingBlock(f any, tickets obj, withBand bool) string {
	prio := str(get(f, "priority"))
	b := pri[prio]
	cve := esc(get(f, "cve"))
	product := productHTML(f)
	if product != "" {
		product = "&nbsp;" + product
	}
	link := "https://nvd.nist.gov/vuln/detail/" + cve
	var badges []string
	if withBand {
		badges = append(badges, badge("background:"+b.fg+";color:#fff;"+badgeBold, esc(get(f, "priority"))))
	}
	if truthy(get(f, "kev")) {
		due := ""
		if truthy(get(f, "kev_due")) {
			due = " &middot; due " + esc(get(f, "kev_due"))
		}
		badges = append(badges, badge("background:#b3001b;color:#fff;"+badgeBold, "KEV"+due))
	}
	if strings.ToLower(str(getOr(f, "ransomware", ""))) == "known" {
		badges = append(badges, badge("background:#5b21b6;color:#fff;"+badgeBold, "RANSOMWARE"))
	}
	if truthy(get(f, "cvss")) {
		badges = append(badges, badge("background:#e2e8f0;color:#1a202c;padding:2px 6px;border-radius:3px;font-size:11px",
			"CVSS "+esc(get(f, "cvss"))+" "+esc(or(get(f, "cvss_severity"), ""))))
	}
	if get(f, "epss") != nil {
		badges = append(badges, badge("background:#e2e8f0;color:#1a202c;padding:2px 6px;border-radius:3px;font-size:11px",
			"EPSS "+pyfmt.Percent(num(get(f, "epss")), 1)))
	}
	st := str(or(get(f, "status"), "UNKNOWN"))
	stColor := "#8a6d00"
	switch st {
	case "PRESENT":
		stColor = "#b3001b"
	case "NOT_PRESENT":
		stColor = "#2f855a"
	}
	badges = append(badges, badge("background:"+stColor+";color:#fff;"+badgeBold, htmlEscape(st)))
	// The lookback is a window, so anything still being discussed reappears
	// every run. is_new is null when there was no history to compare.
	if v, ok := get(f, "is_new").(bool); ok && v {
		badges = append(badges, badge("background:"+emailkit.Navy+";color:#fff;"+badgeBold, "NEW"))
	} else if ok && !v && truthy(get(f, "first_seen")) {
		badges = append(badges, badge("background:#edf2f7;color:#4a5568;padding:2px 6px;border-radius:3px;font-size:11px",
			"since "+htmlEscape(cut(str(get(f, "first_seen")), 10))))
	}
	desc := cut(str(or(get(f, "description"), "No NVD description available.")), 320)
	return `
      <tr><td style="padding:0 0 14px 0">
        <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid ` + b.fg + `;background:` + b.bg + `;border-radius:0 4px 4px 0">
          <tr><td style="padding:12px 14px">
            <div style="font:700 15px -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
              <a href="` + link + `" style="color:` + b.fg + `;text-decoration:none">` + cve + `</a>` + product + `
              <span style="color:#4a5568;font-weight:400">
                &middot; ` + esc(or(get(f, "host_count"), json0)) + ` host(s)</span>
            </div>
            <div style="margin:7px 0">` + strings.Join(badges, " ") + `</div>
            <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#1a202c;margin:6px 0">
              <b>Why it ranks here:</b> ` + esc(get(f, "rationale")) + `
            </div>
            <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#2d3748;margin:6px 0">
              ` + htmlEscape(desc) + `
            </div>
            ` + ticketCellHTML(f, tickets) + `
            ` + qidsCell(f) + `
            <div style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#4a5568;margin-top:4px">
              <b>Hosts:</b> ` + hostsCell(f) + `
            </div>
            ` + providerReasonCell(f) + `
          </td></tr>
        </table>
      </td></tr>`
}
