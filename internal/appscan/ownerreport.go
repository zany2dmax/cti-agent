package appscan

// THE OWNER REPORT
//
// The HTML file attached to the owners lane's email: the fleet's own report
// of what is open on one web application, built from the scanner's API and
// written in the fleet's style. It replaced the scanner's exported report
// (Qualys HTML_ZIPPED) in November 2026, for three reasons:
//
//   - the export's layout is the vendor's to change, and its results section
//     was hard to read (tiny type, the same explanation repeated for every
//     instance);
//   - it carried the scanner's raw evidence, which had to be redacted after
//     the fact, file by file; here nothing reaches the page that did not
//     pass Redact as it was parsed;
//   - it had no address of the site that was scanned.
//
// One self-contained file: inline CSS from the email kit's tokens, no
// script, no external resource, so it opens the same offline, in a mail
// client's viewer and in print. Every value is escaped.
//
// What goes in is decided by the reader: the developers and agencies who
// build the site. Vulnerabilities to fix come first, worst first, one card
// per kind with the explanation once and every place it was found below;
// then sensitive content, the security weaknesses, and - folded away, kept
// for whoever needs them - the scanner's diagnostics.

import (
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

// OwnerReportInput is what one report is built from.
type OwnerReportInput struct {
	Delivery Delivery
	// Findings are the application's open findings of every kind
	// (vulnerabilities, sensitive content, information gathered), evidence
	// already redacted.
	Findings []Finding
	// Remedies are the knowledge base's texts, keyed by finding ID.
	Remedies  map[string]Remedy
	Org       string
	Generated time.Time
}

// owasp2025 names the OWASP Top 10 2025 categories, the mapping Qualys WAS
// reports against (checked on a live console report, November 2026).
var owasp2025 = [10]string{
	"Broken Access Control", "Security Misconfiguration", "Software Supply Chain Failures",
	"Cryptographic Failures", "Injection", "Insecure Design", "Authentication Failures",
	"Software or Data Integrity Failures", "Logging & Alerting Failures",
	"Mishandling of Exceptional Conditions",
}

type sevStyle struct {
	name string
	tone emailkit.Tone
}

func sevOf(s Severity) sevStyle {
	switch s {
	case 5:
		return sevStyle{"Urgent", emailkit.Red}
	case 4:
		return sevStyle{"Critical", emailkit.Amber}
	case 3:
		return sevStyle{"Serious", emailkit.Yellow}
	case 2:
		return sevStyle{"Medium", emailkit.Blue}
	}
	return sevStyle{"Minimal", emailkit.Grey}
}

// kindGroup is one kind of finding (one QID) and every place it was found.
type kindGroup struct {
	id        string
	title     string
	severity  Severity
	potential bool // every instance potential
	items     []Finding
}

func groupKinds(fs []Finding) []kindGroup {
	idx := map[string]int{}
	var out []kindGroup
	for _, f := range fs {
		key := f.ID + "\x00" + f.Title
		i, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, kindGroup{id: f.ID, title: f.Title, severity: f.Severity, potential: true})
			i = len(out) - 1
		}
		g := &out[i]
		g.items = append(g.items, f)
		if f.Severity > g.severity {
			g.severity = f.Severity
		}
		if !f.Potential {
			g.potential = false
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].severity != out[b].severity {
			return out[a].severity > out[b].severity
		}
		if len(out[a].items) != len(out[b].items) {
			return len(out[a].items) > len(out[b].items)
		}
		return out[a].id < out[b].id
	})
	for i := range out {
		items := out[i].items
		sort.SliceStable(items, func(a, b int) bool {
			if items[a].URL != items[b].URL {
				return items[a].URL < items[b].URL
			}
			return items[a].Param < items[b].Param
		})
	}
	return out
}

// RenderOwnerReport is the report, as one HTML document.
func RenderOwnerReport(in OwnerReportInput) []byte {
	d := in.Delivery
	if strings.TrimSpace(d.URL) == "" {
		for _, f := range in.Findings {
			if u := strings.TrimSpace(f.AppURL); u != "" {
				d.URL = u
				break
			}
		}
	}
	var vulns, sensitive, weak, diag []Finding
	ignored := 0
	for _, f := range in.Findings {
		if f.Ignored {
			ignored++
			continue
		}
		switch f.Kind {
		case "SENSITIVE_CONTENT":
			sensitive = append(sensitive, f)
		case "INFORMATION_GATHERED":
			// Qualys files its header and cookie hygiene checks
			// (missing HSTS, CSP, SameSite...) as information gathered at
			// Medium and above; the rest is crawl and TLS diagnostics.
			if f.Severity >= 2 {
				weak = append(weak, f)
			} else {
				diag = append(diag, f)
			}
		default:
			vulns = append(vulns, f)
		}
	}
	var open Counts
	for _, f := range vulns {
		switch f.Severity {
		case 5:
			open.Urgent++
		case 4:
			open.Crit++
		case 3:
			open.Serious++
		case 2:
			open.Medium++
		default:
			open.Minimal++
		}
	}
	kinds := groupKinds(vulns)

	var b strings.Builder
	title := fmt.Sprintf("%s - web application scan report", oneLineName(d.App))
	fmt.Fprintf(&b, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"+
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n",
		h(title), reportCSS())

	when := ""
	if !d.Finished.IsZero() {
		when = d.Finished.Local().Format("Monday 2 January 2006")
	}
	org := strings.TrimSpace(in.Org)
	fmt.Fprintf(&b, `<div class="band"><div class="wrap"><div class="org">%s</div>`+
		`<h1>Web application scan report</h1><div class="sub">%s</div></div></div>`+"\n<div class=\"wrap\">\n",
		h(strings.TrimSpace(org+" · Security")), h(strings.Trim(oneLineName(d.App)+" · "+when, " ·")))

	writeSummary(&b, d, open, kinds, len(sensitive), len(weak), len(diag), ignored, in.Remedies)
	writeCharts(&b, vulns, open, in.Remedies)
	writeKinds(&b, "Vulnerabilities to fix", kinds, len(vulns), in.Remedies, true)
	if len(sensitive) > 0 {
		writeKinds(&b, "Sensitive content", groupKinds(sensitive), len(sensitive), in.Remedies, false)
	}
	writeInfo(&b, weak, diag)

	gen := in.Generated
	if gen.IsZero() {
		gen = time.Now()
	}
	fmt.Fprintf(&b, `<footer><p>Open findings are those the scanner marks New, Reopened or Active. `+
		`Severities are Qualys WAS severities (Urgent down to Minimal).</p>`+
		`<p>This report describes unfixed weaknesses in the application. Please keep it to the people `+
		`working on it and do not forward it further. Cookie values, session identifiers, tokens and login `+
		`headers have been removed; what the scanner sent to prove each finding is shown as it was sent. `+
		`Questions, or to change who receives this: reply to the email it came with.</p>`+
		`<p>%s</p></footer>`+"\n</div>\n</body>\n</html>\n",
		h(fmt.Sprintf("Generated by the %s Agent Fleet AppSec lane from the scanner's API, %s.",
			strings.TrimSpace(orDefault(org, "Security")), gen.Local().Format("2 Jan 2006 15:04"))))
	return []byte(b.String())
}

func writeSummary(b *strings.Builder, d Delivery, open Counts, kinds []kindGroup,
	nSensitive, nWeak, nDiag, ignored int, rem map[string]Remedy) {

	b.WriteString(`<section><h2>Summary</h2><div class="summary"><table class="facts">`)
	row := func(k, v string) { fmt.Fprintf(b, "<tr><th>%s</th><td>%s</td></tr>", h(k), v) }
	row("Application", h(d.App))
	if u := strings.TrimSpace(d.URL); u != "" {
		row("URL scanned", fmt.Sprintf(`<span class="mono">%s</span>`, h(u)))
	} else {
		row("URL scanned", `<span class="muted">not available - the scanner's application record was not reached</span>`)
	}
	if t := strings.TrimSpace(d.ScanTitle); t != "" {
		v := h(t)
		if l := strings.TrimSpace(d.Launch); l != "" {
			v += " · " + h(strings.ToLower(l))
		}
		row("Scan", v)
	}
	if !d.Finished.IsZero() {
		ran := d.Finished.UTC().Format("2 Jan 2006 15:04") + " UTC"
		if !d.Started.IsZero() && !d.LaunchOnly {
			ran = d.Started.UTC().Format("2 Jan 2006 15:04") + " – " + d.Finished.UTC().Format("15:04") + " UTC"
		}
		if d.Duration > 0 {
			ran += " (" + humanDuration(d.Duration) + ")"
		}
		row("Ran", h(ran))
	}
	login := d.AuthLabel
	if login == "unauthenticated scan" {
		login = "None – covers what a visitor can reach without logging in"
	}
	if login != "" {
		row("Login", h(login))
	}
	if d.LinksCrawled > 0 {
		row("Crawled", h(fmt.Sprintf("%d links", d.LinksCrawled)))
	}
	b.WriteString(`</table><div>`)

	tone, lead := emailkit.Green, "<b>No vulnerabilities are open.</b> The scanner found nothing to fix on this run."
	if len(kinds) > 0 {
		k := kinds[0]
		st := sevOf(k.severity)
		tone = st.tone
		n := len(k.items)
		lead = fmt.Sprintf("<b>Worst open: %s.</b> %s", h(st.name), h(k.title))
		if n > 1 {
			lead += h(fmt.Sprintf(", in %d places", n))
		}
		lead += "."
		if r, ok := rem[k.id]; ok && r.Solution != "" {
			lead += " <b>Fix:</b> " + h(firstSentence(r.Solution))
		}
	}
	fmt.Fprintf(b, `<div class="lead" style="border-color:%s;background:%s">%s</div>`, tone.Fg, tone.Bg, lead)

	b.WriteString(`<div class="tiles">`)
	for _, t := range []struct {
		n    int
		name string
		tone emailkit.Tone
	}{{open.Urgent, "Urgent", emailkit.Red}, {open.Crit, "Critical", emailkit.Amber},
		{open.Serious, "Serious", emailkit.Yellow}, {open.Medium, "Medium", emailkit.Blue},
		{open.Minimal, "Minimal", emailkit.Grey}} {
		cls := "tile"
		if t.n == 0 {
			cls += " zero"
		}
		fmt.Fprintf(b, `<div class="%s" style="color:%s;background:%s;border-color:%s"><b>%d</b><span>%s</span></div>`,
			cls, t.tone.Fg, t.tone.Bg, t.tone.Fg, t.n, t.name)
	}
	b.WriteString(`</div><p class="totals">`)
	fmt.Fprintf(b, "<b>%d</b> vulnerabilities to fix", open.Total())
	fmt.Fprintf(b, " · <b>%d</b> sensitive content · <b>%d</b> security weaknesses · %d other items recorded",
		nSensitive, nWeak, nDiag)
	if ignored > 0 {
		fmt.Fprintf(b, " · %d set aside in the scanner's console", ignored)
	}
	if !d.FirstScan && d.ScanDelta != (Counts{}) {
		b.WriteString("<br>This scan compared with the last: " + h(deltaText(d.ScanDelta)))
	} else if d.FirstScan {
		b.WriteString("<br>The first scan of this application, so nothing is compared.")
	}
	b.WriteString(`</p></div></div></section>` + "\n")
}

func writeCharts(b *strings.Builder, vulns []Finding, open Counts, rem map[string]Remedy) {
	if len(vulns) == 0 {
		return
	}
	b.WriteString(`<section><h2>At a glance</h2><div class="charts">`)

	sev := []barRow{{"Urgent", open.Urgent, emailkit.Red}, {"Critical", open.Crit, emailkit.Amber},
		{"Serious", open.Serious, emailkit.Yellow}, {"Medium", open.Medium, emailkit.Blue},
		{"Minimal", open.Minimal, emailkit.Grey}}
	writeBars(b, "By severity", "", sev)

	// By group: the knowledge base's category, when it gives one.
	groups := map[string]*barRow{}
	var order []string
	for _, f := range vulns {
		c := strings.TrimSpace(rem[f.ID].Category)
		if c == "" {
			continue
		}
		g, ok := groups[c]
		if !ok {
			g = &barRow{label: c, tone: emailkit.Grey}
			groups[c] = g
			order = append(order, c)
		}
		g.n++
		if t := sevOf(f.Severity).tone; sevRank(t) > sevRank(g.tone) {
			g.tone = t
		}
	}
	if len(order) > 0 {
		sort.SliceStable(order, func(i, j int) bool { return groups[order[i]].n > groups[order[j]].n })
		var rows []barRow
		for _, c := range order {
			rows = append(rows, *groups[c])
		}
		writeBars(b, "By group", "Bars are coloured by the worst severity in that row.", rows)
	}

	// OWASP Top 10 2025: every category, zeros included, as the scanner's
	// own report draws it. Shown only when the scanner mapped something.
	var owasp [10]barRow
	for i, n := range owasp2025 {
		owasp[i] = barRow{label: fmt.Sprintf("A%02d %s", i+1, n), tone: emailkit.Grey}
	}
	mapped := false
	for _, f := range vulns {
		seen := map[int]bool{}
		for _, o := range f.OWASP {
			n, err := strconv.Atoi(strings.TrimPrefix(o.Code, "A"))
			if err != nil || n < 1 || n > 10 || seen[n] {
				continue
			}
			seen[n] = true
			mapped = true
			r := &owasp[n-1]
			r.n++
			if t := sevOf(f.Severity).tone; sevRank(t) > sevRank(r.tone) {
				r.tone = t
			}
		}
	}
	if mapped {
		b.WriteString(`<div class="owasp">`)
		writeBars(b, "OWASP Top 10 (2025)", "", owasp[:])
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></section>` + "\n")
}

type barRow struct {
	label string
	n     int
	tone  emailkit.Tone
}

func sevRank(t emailkit.Tone) int {
	switch t {
	case emailkit.Red:
		return 5
	case emailkit.Amber:
		return 4
	case emailkit.Yellow:
		return 3
	case emailkit.Blue:
		return 2
	}
	return 1
}

func writeBars(b *strings.Builder, title, note string, rows []barRow) {
	max := 0
	for _, r := range rows {
		if r.n > max {
			max = r.n
		}
	}
	fmt.Fprintf(b, `<div class="chart"><h3>%s</h3>`, h(title))
	for _, r := range rows {
		if r.n == 0 {
			fmt.Fprintf(b, `<div class="bar none"><span class="label">%s</span><span class="track"></span><span class="val">0</span></div>`, h(r.label))
			continue
		}
		pct := float64(r.n) * 100 / float64(max)
		fmt.Fprintf(b, `<div class="bar"><span class="label">%s</span><span class="track"><span class="fill" style="width:%.1f%%;background:%s"></span></span><span class="val">%d</span></div>`,
			h(r.label), pct, r.tone.Fg, r.n)
	}
	if note != "" {
		fmt.Fprintf(b, `<p class="meta note">%s</p>`, h(note))
	}
	b.WriteString(`</div>`)
}

func writeKinds(b *strings.Builder, heading string, kinds []kindGroup, total int, rem map[string]Remedy, isVuln bool) {
	fmt.Fprintf(b, `<section><h2>%s <span class="n">(%d`, h(heading), total)
	if len(kinds) > 1 {
		fmt.Fprintf(b, ", in %d kinds", len(kinds))
	}
	b.WriteString(`)</span></h2>`)
	if len(kinds) == 0 {
		b.WriteString(`<p class="hint">Nothing open.</p></section>` + "\n")
		return
	}
	if isVuln {
		b.WriteString(`<p class="hint">Worst first. Each card explains the problem once; the table lists every place the scanner found it. Open a row for what the scanner sent and what came back.</p>`)
	}
	for _, k := range kinds {
		st := sevOf(k.severity)
		r, hasRem := rem[k.id]
		fmt.Fprintf(b, `<article class="finding" style="border-left-color:%s"><header>`, st.tone.Fg)
		fmt.Fprintf(b, `<span class="sev" style="color:%s;background:%s">%s</span>`, st.tone.Fg, st.tone.Bg, st.name)
		if k.potential {
			b.WriteString(`<span class="tag">Potential &ndash; likely, but not confirmed by the scanner</span>`)
		} else {
			b.WriteString(`<span class="tag">Confirmed</span>`)
		}
		places := "1 place"
		if len(k.items) != 1 {
			places = fmt.Sprintf("%d places", len(k.items))
		}
		fmt.Fprintf(b, `<span class="tag">%s</span>`, places)
		fmt.Fprintf(b, `<h3><span class="qid">%s</span>%s</h3>`, h(k.id), h(k.title))

		var meta []string
		f0 := k.items[0]
		if v := maxCVSS(k.items); v > 0 {
			meta = append(meta, fmt.Sprintf("CVSS <b>%.1f</b>", v))
		}
		if hasRem && len(r.CVEs) > 0 {
			meta = append(meta, "CVE <b>"+h(strings.Join(r.CVEs, ", "))+"</b>")
		}
		if len(f0.CWE) > 0 {
			var cw []string
			for _, c := range f0.CWE {
				cw = append(cw, strconv.Itoa(c))
			}
			meta = append(meta, "CWE <b>"+h(strings.Join(cw, ", "))+"</b>")
		}
		for _, o := range f0.OWASP {
			meta = append(meta, "OWASP <b>"+h(owaspLabel(o))+"</b>")
		}
		if q := maxQDS(k.items); q > 0 {
			meta = append(meta, fmt.Sprintf("QDS <b>%d</b>", q))
		}
		if len(meta) > 0 {
			b.WriteString(`<div class="meta"><span>` + strings.Join(meta, "</span><span>") + `</span></div>`)
		}
		b.WriteString(`</header>`)

		if hasRem && (r.Diagnosis != "" || r.Consequence != "" || r.Solution != "") {
			b.WriteString(`<div class="explain">`)
			fmt.Fprintf(b, `<div><h4>What it is</h4>%s</div>`, paras(orDefault(r.Diagnosis, "Not described by the scanner.")))
			fmt.Fprintf(b, `<div><h4>Why it matters</h4>%s</div>`, paras(orDefault(r.Consequence, "Not described by the scanner.")))
			fmt.Fprintf(b, `<div class="fix"><h4>How to fix</h4>%s</div>`, paras(orDefault(r.Solution, "Not described by the scanner - ask the security team.")))
			b.WriteString(`</div>`)
		} else {
			b.WriteString(`<p class="hint pad">The scanner's knowledge base had no description for this finding; the security team can supply one.</p>`)
		}

		b.WriteString(`<table class="inst"><tr><th class="where">Where</th><th>Parameter</th><th>Status</th><th>Last detected</th></tr>`)
		for _, f := range k.items {
			b.WriteString(`<tr><td><code>` + h(orDefault(f.URL, "-")) + `</code>`)
			writeEvidence(b, f.Evidence)
			param := strings.TrimSpace(f.Param)
			if param == "" || strings.HasPrefix(strings.ToLower(param), "no param") {
				param = "&ndash;"
			} else {
				param = "<code>" + h(param) + "</code>"
			}
			seen := "&ndash;"
			if !f.LastSeen.IsZero() {
				seen = h(f.LastSeen.Local().Format("2 Jan 2006"))
			}
			fmt.Fprintf(b, `</td><td>%s</td><td>%s</td><td>%s</td></tr>`, param, statusChip(f.Status), seen)
		}
		b.WriteString(`</table></article>`)
	}
	b.WriteString(`</section>` + "\n")
}

func writeEvidence(b *strings.Builder, e *Evidence) {
	if e == nil || (e.Link == "" && e.Payload == "" && e.Proof == "") {
		return
	}
	b.WriteString(`<details class="ev"><summary>What the scanner sent and saw</summary>`)
	if e.Link != "" {
		fmt.Fprintf(b, `<div class="k">Request</div><pre>%s</pre>`, h(strings.TrimSpace(e.Method+" "+e.Link)))
	}
	if e.Payload != "" {
		fmt.Fprintf(b, `<div class="k">Payload</div><pre>%s</pre>`, h(e.Payload))
	}
	if e.Proof != "" {
		fmt.Fprintf(b, `<div class="k">What came back</div><pre>%s</pre>`, h(e.Proof))
	}
	if len(e.AccessPath) > 0 {
		fmt.Fprintf(b, `<div class="k">Reached from</div><pre>%s</pre>`, h(strings.Join(e.AccessPath, "\n")))
	}
	if e.Authenticated {
		b.WriteString(`<div class="k">Found while logged in as the scan account</div>`)
	}
	b.WriteString(`</details>`)
}

func writeInfo(b *strings.Builder, weak, diag []Finding) {
	b.WriteString(`<section><h2>Security weaknesses <span class="n">(` + strconv.Itoa(len(weak)) + `)</span></h2>`)
	if len(weak) == 0 {
		b.WriteString(`<p class="hint">None recorded.</p>`)
	} else {
		b.WriteString(`<p class="hint">Not counted as vulnerabilities, but each makes an attack easier. Most are a one-line web server setting; worth doing alongside the fixes above.</p>`)
		writeList(b, weak)
	}
	if len(diag) > 0 {
		fmt.Fprintf(b, `<details class="more"><summary>What the scanner also recorded (%d items: scan diagnostics, TLS and crawl information)</summary>`, len(diag))
		writeList(b, diag)
		b.WriteString(`</details>`)
	}
	b.WriteString(`</section>` + "\n")
}

func writeList(b *strings.Builder, fs []Finding) {
	seen := map[string]bool{}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].Title < fs[j].Title
	})
	b.WriteString(`<table class="list">`)
	for _, f := range fs {
		k := f.ID + "\x00" + f.Title
		if seen[k] {
			continue
		}
		seen[k] = true
		fmt.Fprintf(b, `<tr><td class="q">%s</td><td>%s</td></tr>`, h(f.ID), h(f.Title))
	}
	b.WriteString(`</table>`)
}

func statusChip(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	t := emailkit.Grey
	switch s {
	case "NEW":
		t = emailkit.Red
	case "REOPENED":
		t = emailkit.Amber
	case "":
		return "&ndash;"
	}
	return fmt.Sprintf(`<span class="st" style="color:%s;background:%s">%s</span>`, t.Fg, t.Bg, h(s))
}

func owaspLabel(o OWASPRef) string {
	if n, err := strconv.Atoi(strings.TrimPrefix(o.Code, "A")); err == nil && n >= 1 && n <= 10 {
		return fmt.Sprintf("A%02d %s", n, owasp2025[n-1])
	}
	return o.Name
}

func maxCVSS(fs []Finding) float64 {
	m := 0.0
	for _, f := range fs {
		if f.CVSS > m {
			m = f.CVSS
		}
	}
	return m
}

func maxQDS(fs []Finding) int {
	m := 0
	for _, f := range fs {
		if f.QDS > m {
			m = f.QDS
		}
	}
	return m
}

func deltaText(c Counts) string {
	var parts []string
	for _, p := range []struct {
		n    int
		name string
	}{{c.Urgent, "Urgent"}, {c.Crit, "Critical"}, {c.Serious, "Serious"}, {c.Medium, "Medium"}, {c.Minimal, "Minimal"}} {
		switch {
		case p.n > 0:
			parts = append(parts, fmt.Sprintf("+%d %s", p.n, p.name))
		case p.n < 0:
			parts = append(parts, fmt.Sprintf("−%d %s", -p.n, p.name))
		}
	}
	if len(parts) == 0 {
		return "no change"
	}
	return strings.Join(parts, ", ")
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	hrs, mins := int(d.Hours()), int(d.Minutes())%60
	switch {
	case hrs == 0:
		return fmt.Sprintf("%d min", mins)
	case mins == 0:
		return fmt.Sprintf("%d h", hrs)
	}
	return fmt.Sprintf("%d h %d min", hrs, mins)
}

// firstSentence is the opening sentence of a knowledge-base text, for the
// summary's one-line fix. Bounded, so a text with no full stop stays short.
func firstSentence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i > 0 && i < 240 {
		return s[:i+1]
	}
	r := []rune(s)
	if len(r) > 240 {
		return string(r[:240]) + "…"
	}
	return s
}

// paras renders plain text as escaped paragraphs.
func paras(s string) string {
	var b strings.Builder
	for _, p := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n\n") {
		if p = strings.TrimSpace(p); p != "" {
			b.WriteString("<p>" + strings.ReplaceAll(h(p), "\n", "<br>") + "</p>")
		}
	}
	return b.String()
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func h(s string) string { return html.EscapeString(s) }

// reportCSS is the report's stylesheet, from the email kit's tokens so the
// report and the emails cannot drift apart.
func reportCSS() string {
	r := strings.NewReplacer(
		"{font}", emailkit.Font, "{mono}", emailkit.Mono, "{page}", emailkit.PageBG,
		"{navy}", emailkit.Navy, "{band}", emailkit.BandText, "{ink}", emailkit.Ink,
		"{soft}", emailkit.Soft, "{muted}", emailkit.Muted, "{rule}", emailkit.Rule,
		"{greybg}", emailkit.Grey.Bg, "{green}", emailkit.Green.Fg, "{greenbg}", emailkit.Green.Bg,
		"{blue}", emailkit.Blue.Fg, "{yellow}", emailkit.Yellow.Fg, "{yellowbg}", emailkit.Yellow.Bg)
	return r.Replace(`
*{box-sizing:border-box}
body{margin:0;background:{page};color:{ink};font:15px/1.5 {font}}
.wrap{max-width:1040px;margin:0 auto;padding:0 16px 40px}
code,pre,.mono{font-family:{mono}}
.muted{color:{muted}}
.band{background:{navy};color:#fff;padding:22px 0 20px}
.band .org{color:{band};font-size:13px;letter-spacing:.04em;text-transform:uppercase}
.band h1{margin:4px 0 2px;font-size:24px;font-weight:600}
.band .sub{color:{band};font-size:15px}
section{background:#fff;border:1px solid {rule};border-radius:6px;margin-top:18px;padding:18px 20px}
h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:{soft};margin:0 0 12px}
h2 .n{color:{muted};font-weight:400}
.summary{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr);gap:22px}
.facts{width:100%;border-collapse:collapse;font-size:14px}
.facts th{text-align:left;color:{muted};font-weight:400;padding:3px 12px 3px 0;white-space:nowrap;vertical-align:top;width:1%}
.facts td{padding:3px 0;overflow-wrap:anywhere}
.lead{border-left:4px solid;padding:10px 12px;border-radius:0 4px 4px 0;margin-bottom:12px;font-size:14px}
.tiles{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border-radius:4px;overflow:hidden}
.tile{text-align:center;padding:10px 4px 8px;border-top:3px solid}
.tile b{display:block;font-size:24px;font-weight:600;line-height:1.1}
.tile span{font-size:11px;letter-spacing:.05em;text-transform:uppercase}
.zero{opacity:.55}
.totals{margin:12px 0 0;font-size:14px;color:{soft}}
.totals b{color:{ink}}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:22px 30px}
.charts .owasp{grid-column:1/-1}
.chart h3{font-size:13px;margin:0 0 8px;font-weight:600}
.bar{display:grid;grid-template-columns:minmax(0,1fr) 1.4fr 28px;align-items:center;gap:8px;font-size:12.5px;margin:3px 0}
.owasp .bar{grid-template-columns:minmax(0,.9fr) 2fr 28px}
.bar .label{color:{soft};text-align:right}
.bar .track,.bar .fill{display:block}
.bar .track{background:{greybg};height:10px;border-radius:2px;overflow:hidden}
.bar .fill{height:100%;border-radius:2px;min-width:3px}
.bar .val{font-variant-numeric:tabular-nums;font-weight:600}
.bar.none .label,.bar.none .val{color:{muted};font-weight:400}
.meta{font-size:12.5px;color:{soft}}
.meta span{margin-right:14px;white-space:nowrap}
.meta b{color:{ink};font-weight:600}
.note{margin-top:10px}
.finding{border:1px solid {rule};border-left:4px solid;border-radius:0 6px 6px 0;margin:14px 0 0}
.finding>header{padding:12px 14px 10px}
.sev{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:2px 7px;border-radius:3px;margin-right:6px}
.tag{display:inline-block;font-size:11px;color:{soft};border:1px solid {rule};padding:1px 6px;border-radius:3px;margin-right:6px}
.finding h3{font-size:16px;margin:6px 0 4px}
.finding h3 .qid{color:{muted};font-weight:400;font-family:{mono};font-size:13px;margin-right:6px}
.explain{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;padding:4px 14px 12px;font-size:14px}
.explain h4{font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;color:{muted};margin:0 0 3px}
.explain p{margin:0 0 6px}
.explain .fix{background:{greenbg};border-radius:4px;padding:8px 10px}
.explain .fix h4{color:{green}}
.pad{padding:0 14px}
table.inst{width:100%;border-collapse:collapse;font-size:13px}
table.inst th{text-align:left;font-weight:600;color:{soft};background:{greybg};padding:6px 14px;border-top:1px solid {rule}}
table.inst th.where{width:44%}
table.inst td{padding:6px 14px;border-top:1px solid {rule};vertical-align:top;overflow-wrap:anywhere}
.st{font-size:11px;font-weight:700;letter-spacing:.04em;padding:1px 6px;border-radius:3px}
details.ev summary{cursor:pointer;color:{blue};font-size:12.5px}
details.ev pre{white-space:pre-wrap;word-break:break-all;background:#f7f8fa;border:1px solid {rule};border-radius:4px;padding:8px 10px;font-size:12px;margin:6px 0 2px}
details.ev .k{color:{muted};font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
table.list{width:100%;border-collapse:collapse;font-size:13.5px}
table.list td{padding:5px 8px 5px 0;border-top:1px solid {rule}}
table.list td.q{font-family:{mono};color:{muted};width:70px;font-size:12.5px}
details.more summary{cursor:pointer;color:{blue};font-size:14px;margin-top:10px}
.hint{font-size:13px;color:{soft};margin:-4px 0 10px}
footer{font-size:12.5px;color:{muted};margin-top:18px;padding:0 4px}
footer p{margin:4px 0}
@media (max-width:760px){.summary,.charts,.explain{grid-template-columns:1fr}.tile b{font-size:20px}}
@media print{body{background:#fff}section{break-inside:avoid-page}details.ev:not([open]){display:none}}
`)
}
