package domains

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"
)

// Block is the rendered report.
type Block struct {
	Subject string
	Text    string
	HTML    string
}

// Report is everything one run knows.
type Report struct {
	Now      time.Time
	Results  []Result
	Findings []Finding // from Evaluate
	Changes  []Finding // from Diff
	// Registrar is the account consulted, "" when it was not; RegistrarErr
	// says why when it was attempted and failed.
	Registrar    string
	RegistrarErr string
	Problems     []string // inventory file problems
	FirstRun     bool     // no previous state, so no changes can be reported
	Selectors    []string
}

// NotChecked is said in every report, because a check that is silently
// absent reads as a check that passed.
var NotChecked = []string{
	"CAA and DNSSEC (the fleet's Go code is standard-library only, which cannot query them)",
	"SMTP STARTTLS and MTA-STS on the MX hosts",
	"DKIM selectors other than those listed - a key at any other selector is invisible to this check",
	"subdomains not listed in domains.txt",
}

func orgName() string {
	if s := strings.TrimSpace(os.Getenv("FLEET_ORG")); s != "" {
		return s
	}
	return "Security"
}

func e(s string) string { return html.EscapeString(s) }

func (r Report) high() []Finding    { return bySev(r.Findings, High) }
func (r Report) medium() []Finding  { return bySev(r.Findings, Medium) }
func (r Report) info() []Finding    { return bySev(r.Findings, Info) }
func (r Report) changes() []Finding { return r.Changes }

func bySev(f []Finding, s Severity) []Finding {
	var out []Finding
	for _, x := range f {
		if x.Sev == s {
			out = append(out, x)
		}
	}
	return out
}

func (r Report) counts() (high, medium, changed int) {
	high, medium = len(r.high()), len(r.medium())
	for _, c := range r.Changes {
		switch c.Sev {
		case High:
			high++
		case Medium:
			medium++
		}
	}
	return high, medium, len(r.Changes)
}

func (r Report) live() int {
	n := 0
	for _, x := range r.Results {
		if x.Live() {
			n++
		}
	}
	return n
}

// Subject leads with the fleet name, as every lane's does.
func (r Report) Subject() string {
	h, m, _ := r.counts()
	tag := ""
	if r.Registrar == "" {
		tag = " [REGISTRAR NOT CHECKED]"
	}
	var parts []string
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d High", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%d Medium", m))
	}
	body := "no issues"
	if len(parts) > 0 {
		body = strings.Join(parts, " - ")
	}
	return fmt.Sprintf("CTI Fleet Domains %s%s: %s across %d domains",
		r.Now.Format("Jan 02"), tag, body, len(r.Results))
}

func (r Report) leadLine() string {
	h, m, c := r.counts()
	var s string
	switch {
	case h > 0:
		s = fmt.Sprintf("%d High finding(s) need action this week; %d Medium to review.", h, m)
	case m > 0:
		s = fmt.Sprintf("Nothing urgent. %d Medium finding(s) to review.", m)
	default:
		s = "Every domain checked matches what it is supposed to be."
	}
	if r.FirstRun {
		s += " First run: there is no previous week to compare with, so no changes are reported."
	} else if c > 0 {
		s += fmt.Sprintf(" %d change(s) since last week.", c)
	}
	if r.Registrar == "" {
		why := "it was skipped"
		if r.RegistrarErr != "" {
			why = "it failed: " + r.RegistrarErr
		}
		s += " The registrar was NOT consulted (" + why + "), so expiry, lock, " +
			"auto-renew and inventory-vs-account checks did not run."
	}
	return s
}

// ─── per-domain summary for the inventory table ─────────────────────────────

func webState(r Result) string {
	var parts []string
	for _, w := range r.Web {
		label := w.Host
		if w.Host == r.Entry.Name {
			label = "apex"
		} else if strings.HasPrefix(w.Host, "www.") {
			label = "www"
		}
		var st string
		switch {
		case w.Dangling:
			st = "DANGLING CNAME"
		case !w.Addrs.Known():
			st = "DNS error"
		case !w.Addrs.Present():
			st = "no DNS"
		case !w.Live():
			st = "no answer"
		case w.ParkedBy() != "":
			st = "parked"
		case w.HTTPS.OK():
			st = "live"
		default:
			st = "live (HTTP only)"
		}
		parts = append(parts, label+" "+st)
	}
	return strings.Join(parts, ", ")
}

func mailState(r Result) string {
	m := r.Mail
	var p []string
	switch {
	case !m.SPF.Known():
		p = append(p, "SPF ?")
	case !m.SPF.Present():
		p = append(p, "SPF none")
	case len(m.SPF.Values) > 1:
		p = append(p, "SPF x2")
	default:
		a := SPFAll(m.SPF.Values[0])
		if a == "" {
			a = "no all"
		}
		p = append(p, "SPF "+a)
	}
	switch {
	case m.DKIM.Wildcard:
		p = append(p, "DKIM ?")
	case len(m.DKIM.Found) > 0:
		p = append(p, "DKIM "+strings.Join(m.DKIM.Found, "/"))
	default:
		p = append(p, "DKIM none")
	}
	switch {
	case !m.DMARC.Known():
		p = append(p, "DMARC ?")
	case !m.DMARC.Present():
		p = append(p, "DMARC none")
	case len(m.DMARC.Values) > 1:
		p = append(p, "DMARC x2")
	default:
		eff := ParseDMARC(m.DMARC.Values[0]).Effective(m.DMARCFrom != r.Entry.Name)
		if eff == "" {
			eff = "invalid"
		}
		if m.DMARCFrom != r.Entry.Name {
			eff += " (parent)"
		}
		p = append(p, "DMARC "+eff)
	}
	switch {
	case !m.MX.Known():
		p = append(p, "MX ?")
	case !m.MX.Present():
		p = append(p, "no MX")
	case len(m.MX.Values) == 1 && m.MX.Values[0] == ".":
		p = append(p, "null MX")
	default:
		p = append(p, "MX")
	}
	return strings.Join(p, " · ")
}

func role(en Entry) string {
	if en.Sends {
		return "sends"
	}
	return "no mail"
}

// ─── grouping ───────────────────────────────────────────────────────────────

type group struct {
	domain string
	items  []Finding
}

// grouped keeps one heading per domain: five lines about one domain read as
// one problem, not five.
func grouped(f []Finding) []group {
	var out []group
	idx := map[string]int{}
	for _, x := range f {
		i, ok := idx[x.Domain]
		if !ok {
			i = len(out)
			idx[x.Domain] = i
			out = append(out, group{domain: x.Domain})
		}
		out[i].items = append(out[i].items, x)
	}
	return out
}

// ─── text ───────────────────────────────────────────────────────────────────

func (r Report) text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n%s\n", r.Subject(), strings.Repeat("=", len(r.Subject())), r.leadLine())

	section := func(title string, f []Finding, tagSev bool) {
		if len(f) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d)\n%s\n", title, len(f), strings.Repeat("-", len(title)+5))
		for _, g := range grouped(f) {
			fmt.Fprintf(&b, "  %s\n", g.domain)
			for _, x := range g.items {
				tag := ""
				if tagSev {
					tag = "[" + x.Sev.String() + "] "
				}
				fmt.Fprintf(&b, "    - %s%s\n", tag, x.Text)
			}
		}
	}
	section("NEEDS ACTION", r.high(), false)
	section("CHANGED SINCE LAST WEEK", r.changes(), true)
	section("REVIEW", r.medium(), false)
	section("NOTES", r.info(), false)

	if len(r.Problems) > 0 {
		fmt.Fprintf(&b, "\nINVENTORY FILE PROBLEMS (%d)\n", len(r.Problems))
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}

	fmt.Fprintf(&b, "\nINVENTORY (%d domains, %d live)\n", len(r.Results), r.live())
	for _, x := range sortedResults(r.Results) {
		fmt.Fprintf(&b, "  %-32s %-8s %s\n      %s\n", x.Entry.Name, role(x.Entry), webState(x), mailState(x))
	}

	fmt.Fprintf(&b, "\nNOT CHECKED\n")
	for _, s := range r.notChecked() {
		fmt.Fprintf(&b, "  - %s\n", s)
	}
	fmt.Fprintf(&b, "\nGenerated by the %s CTI agent fleet.\n", orgName())
	return b.String()
}

func (r Report) notChecked() []string {
	out := append([]string(nil), NotChecked...)
	if len(r.Selectors) > 0 {
		out[2] = "DKIM selectors other than " + strings.Join(r.Selectors, ", ") +
			" - a key at any other selector is invisible to this check"
	}
	return out
}

func sortedResults(in []Result) []Result {
	out := append([]Result(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Entry.Name < out[j].Entry.Name })
	return out
}

// ─── HTML ───────────────────────────────────────────────────────────────────
//
// The daily brief's house style: table layout, inline CSS, 640px, the navy
// header band. Domain names are text, never links.

const font = `-apple-system,Segoe UI,Helvetica,Arial,sans-serif`

func (r Report) html() string {
	var b strings.Builder
	h, m, c := r.counts()
	fmt.Fprintf(&b, `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title></head>
<body style="margin:0;padding:0;background:#eef1f5">
<table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
       style="background:#eef1f5"><tr><td align="center" style="padding:16px 8px">
<table width="640" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:640px;background:#fff;border-radius:6px;overflow:hidden">

  <tr><td style="background:#12203a;padding:16px 20px">
    <div style="font:700 12px %s;color:#9fb0cc;letter-spacing:1.2px;text-transform:uppercase">%s</div>
    <div style="font:700 17px %s;color:#fff">CTI Domains Weekly</div>
    <div style="font:400 12px %s;color:#9fb0cc;margin-top:3px">Week of %s</div></td></tr>
`, e(r.Subject()), font, e(orgName()), font, font, e(r.Now.Format("Monday 2 January 2006")))

	leadFg, leadBg := "#2f855a", "#f0fff4"
	if h > 0 {
		leadFg, leadBg = "#b3001b", "#fdecee"
	} else if m > 0 || r.Registrar == "" {
		leadFg, leadBg = "#b25000", "#fff4e5"
	}
	fmt.Fprintf(&b, `
  <tr><td style="padding:16px 20px 0 20px">
    <table width="100%%" cellpadding="0" cellspacing="0" role="presentation">
      <tr><td style="background:%s;border-left:4px solid %s;padding:12px 14px;
                     font:400 14px/1.55 %s;color:#1a202c">%s</td></tr>
    </table></td></tr>
`, leadBg, leadFg, font, e(r.leadLine()))

	type tile struct {
		label  string
		n      int
		fg, bg string
	}
	tiles := []tile{
		{"HIGH", h, "#b3001b", "#fdecee"},
		{"MEDIUM", m, "#b25000", "#fff4e5"},
		{"CHANGED", c, "#2c5282", "#ebf4ff"},
		{"LIVE", r.live(), "#2f855a", "#f0fff4"},
		{"DOMAINS", len(r.Results), "#4a5568", "#f4f5f7"},
	}
	b.WriteString(`
  <tr><td style="padding:14px 20px 0 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>`)
	for _, t := range tiles {
		fmt.Fprintf(&b, `
      <td width="20%%" align="center" style="background:%s;border-top:3px solid %s;padding:10px 4px">
        <div style="font:700 24px %s;color:%s">%d</div>
        <div style="font:700 10px %s;color:%s;letter-spacing:.5px">%s</div></td>`,
			t.bg, t.fg, font, t.fg, t.n, font, t.fg, t.label)
	}
	b.WriteString(`
    </tr></table></td></tr>
  <tr><td style="padding:16px 20px 4px 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">`)

	cards := func(title, fg, bg string, f []Finding, tagSev bool) {
		if len(f) == 0 {
			return
		}
		sectionHTML(&b, fmt.Sprintf("%s (%d)", title, len(f)), fg)
		for _, g := range grouped(f) {
			var lines strings.Builder
			for _, x := range g.items {
				tag := ""
				if tagSev {
					tag = "<b>" + e(x.Sev.String()) + "</b> &middot; "
				}
				fmt.Fprintf(&lines, `<div style="margin-top:4px">%s%s</div>`, tag, e(x.Text))
			}
			fmt.Fprintf(&b, `
      <tr><td style="padding:0 0 10px 0">
        <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid %s;background:%s;border-radius:0 4px 4px 0">
          <tr><td style="padding:10px 13px">
            <div style="font:700 14px %s;color:#1a202c">%s</div>
            <div style="font:400 13px/1.5 %s;color:#1a202c">%s</div>
          </td></tr></table></td></tr>`, fg, bg, font, e(g.domain), font, lines.String())
		}
	}
	cards("NEEDS ACTION", "#b3001b", "#fdecee", r.high(), false)
	cards("CHANGED SINCE LAST WEEK", "#2c5282", "#ebf4ff", r.changes(), true)
	cards("REVIEW", "#b25000", "#fff4e5", r.medium(), false)
	cards("NOTES", "#4a5568", "#f4f5f7", r.info(), false)

	if len(r.Problems) > 0 {
		sectionHTML(&b, fmt.Sprintf("INVENTORY FILE PROBLEMS (%d)", len(r.Problems)), "#b25000")
		for _, p := range r.Problems {
			itemHTML(&b, p)
		}
	}

	sectionHTML(&b, fmt.Sprintf("INVENTORY (%d DOMAINS, %d LIVE)", len(r.Results), r.live()), "#12203a")
	fmt.Fprintf(&b, `
      <tr><td style="padding:0 0 10px 0">
        <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
               style="font:400 12px %s;border-collapse:collapse">`, font)
	for _, x := range sortedResults(r.Results) {
		fmt.Fprintf(&b, `
          <tr><td style="padding:5px 8px 5px 0;border-bottom:1px solid #edf2f7;color:#1a202c;
                         font-weight:700;word-break:break-all">%s
                <div style="font-weight:400;color:#718096;font-size:11px">%s</div></td>
              <td style="padding:5px 8px;border-bottom:1px solid #edf2f7;color:#4a5568">%s
                <div style="color:#718096;font-size:11px">%s</div></td></tr>`,
			e(x.Entry.Name), e(role(x.Entry)), e(webState(x)), e(mailState(x)))
	}
	b.WriteString(`
        </table></td></tr>
    </table></td></tr>`)

	var nc strings.Builder
	for _, s := range r.notChecked() {
		nc.WriteString("&bull; " + e(s) + "<br>")
	}
	fmt.Fprintf(&b, `
  <tr><td style="padding:8px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:400 11px/1.6 %s;color:#718096">
      <b>Not checked:</b><br>%s
      Generated by the %s CTI agent fleet.
    </div></td></tr>

</table></td></tr></table></body></html>`, font, nc.String(), e(orgName()))
	return b.String()
}

func sectionHTML(b *strings.Builder, title, colour string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:6px 0 8px 0">
        <div style="font:700 13px %s;color:%s;letter-spacing:.6px;text-transform:uppercase;
                    border-bottom:2px solid %s;padding-bottom:5px">%s</div></td></tr>`,
		font, colour, colour, e(title))
}

func itemHTML(b *strings.Builder, s string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:0 0 8px 0">
        <div style="font:400 13px/1.55 %s;color:#4a5568">%s</div></td></tr>`, font, e(s))
}

// Render builds both forms.
func (r Report) Render() Block {
	return Block{Subject: r.Subject(), Text: r.text(), HTML: r.html()}
}
