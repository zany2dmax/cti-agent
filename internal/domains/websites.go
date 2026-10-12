package domains

import (
	"fmt"
	"strings"
)

// WHICH DOMAINS HAVE A WEBSITE
//
// The first question sitecheck.go was written to answer, and the report used
// to bury it: the web state of each domain was there, but only in the
// inventory table at the bottom, interleaved with mail records, so "which of
// our domains has a live site" meant reading 94 rows. This puts the answer
// first, one group per kind of answer.

type siteClass int

const (
	siteLive      siteClass = iota // serves its own working page
	siteRedirect                   // serves a redirect to another domain
	siteRegistrar                  // live, on the registrar's own hosting
	siteParked                     // a parking or for-sale page
	siteBroken                     // has addresses, but no working page
	siteNone                       // no address records: no website at all
	siteUnknown                    // the address lookup failed
)

var siteGroups = []struct {
	class siteClass
	title string
}{
	{siteLive, "Live website"},
	{siteRedirect, "Redirects to another domain"},
	{siteRegistrar, "Live, on the registrar's hosting (Website Builder or lander)"},
	{siteParked, "Parked or for sale"},
	{siteBroken, "Has DNS but no working page"},
	{siteNone, "No website (no address records)"},
	{siteUnknown, "Not checked (DNS lookup failed)"},
}

// site is one domain's answer.
type site struct {
	domain string
	class  siteClass
	detail string
}

// classifySite decides what a domain's web presence is, from the apex and
// www probes together: a domain whose apex has no records but whose www
// serves a site has a website.
func classifySite(r Result) site {
	s := site{domain: r.Entry.Name}
	for _, w := range r.Web {
		if !w.Live() || w.ParkedBy() != "" {
			continue
		}
		if t := redirectHost(w); t != "" && !sameSite(t, r.Entry.Name) {
			s.class, s.detail = siteRedirect, "→ "+t
			return s
		}
		s.class = siteLive
		if w.RegistrarPage() != "" {
			s.class = siteRegistrar
		}
		s.detail = liveDetail(w)
		return s
	}
	for _, w := range r.Web {
		if p := w.ParkedBy(); p != "" {
			s.class, s.detail = siteParked, "parked ("+p+")"
			return s
		}
	}
	anyAddr, anyErr := false, false
	for _, w := range r.Web {
		switch {
		case !w.Addrs.Known():
			anyErr = true
		case w.Addrs.Present():
			anyAddr = true
		}
	}
	switch {
	case anyAddr:
		s.class, s.detail = siteBroken, webState(r)
	case anyErr:
		s.class, s.detail = siteUnknown, webState(r)
	default:
		s.class = siteNone
	}
	return s
}

// sameSite reports whether host is domain or one of its subdomains, so a
// redirect from example.com to www.example.com is not "another domain".
func sameSite(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// liveDetail is the host the site ended up on, its status and its page
// title. The host, not the URL: the report carries no links, and a full URL
// is one a mail client turns into one.
func liveDetail(w Web) string {
	b := w.Best()
	var p []string
	if t := redirectHost(w); t != "" {
		p = append(p, t)
	} else {
		p = append(p, w.Host)
	}
	p = append(p, fmt.Sprintf("HTTP %d", b.Status))
	if !w.HTTPS.Serving() {
		p = append(p, "HTTP only")
	}
	if t := strings.Join(strings.Fields(b.Title), " "); t != "" {
		if len([]rune(t)) > 70 {
			t = string([]rune(t)[:67]) + "..."
		}
		p = append(p, fmt.Sprintf("%q", t))
	}
	return strings.Join(p, " · ")
}

// sites classifies every domain, in name order.
func (r Report) sites() map[siteClass][]site {
	out := map[siteClass][]site{}
	for _, x := range sortedResults(r.Results) {
		s := classifySite(x)
		out[s.class] = append(out[s.class], s)
	}
	return out
}

// websiteLine is the sentence the lead carries.
func (r Report) websiteLine() string {
	g := r.sites()
	n := func(c siteClass) int { return len(g[c]) }
	s := fmt.Sprintf("Websites: %d domain(s) serve a live site", n(siteLive)+n(siteRegistrar))
	if n(siteRedirect) > 0 {
		s += fmt.Sprintf(", %d redirect to another domain", n(siteRedirect))
	}
	if n(siteParked) > 0 {
		s += fmt.Sprintf(", %d are parked", n(siteParked))
	}
	if n(siteBroken) > 0 {
		s += fmt.Sprintf(", %d have DNS but no working page", n(siteBroken))
	}
	s += fmt.Sprintf(", %d have no website.", n(siteNone))
	if n(siteUnknown) > 0 {
		s += fmt.Sprintf(" %d could not be checked.", n(siteUnknown))
	}
	return s
}

// websitesText is the WEBSITES section of the text report.
func (r Report) websitesText(b *strings.Builder) {
	g := r.sites()
	fmt.Fprintf(b, "\nWEBSITES\n--------\n")
	for _, grp := range siteGroups {
		list := g[grp.class]
		if len(list) == 0 {
			continue
		}
		fmt.Fprintf(b, "  %s (%d)\n", grp.title, len(list))
		if grp.class == siteNone {
			// Names only: the reader needs the list, not 60 identical rows.
			names := make([]string, len(list))
			for i, s := range list {
				names[i] = s.domain
			}
			for _, line := range wrapNames(names, 72) {
				fmt.Fprintf(b, "    %s\n", line)
			}
			continue
		}
		for _, s := range list {
			fmt.Fprintf(b, "    %-32s %s\n", s.domain, s.detail)
		}
	}
}

// websitesHTML is the same section for the email.
func (r Report) websitesHTML(b *strings.Builder) {
	g := r.sites()
	sectionHTML(b, "WEBSITES", "#2f855a")
	for _, grp := range siteGroups {
		list := g[grp.class]
		if len(list) == 0 {
			continue
		}
		var rows strings.Builder
		if grp.class == siteNone {
			names := make([]string, len(list))
			for i, s := range list {
				names[i] = e(s.domain)
			}
			rows.WriteString(`<div style="margin-top:4px">` + strings.Join(names, ", ") + `</div>`)
		} else {
			for _, s := range list {
				fmt.Fprintf(&rows, `<div style="margin-top:4px"><b>%s</b> &nbsp;%s</div>`,
					e(s.domain), e(s.detail))
			}
		}
		fmt.Fprintf(b, `
      <tr><td style="padding:0 0 10px 0">
        <div style="font:700 13px %s;color:#1a202c">%s (%d)</div>
        <div style="font:400 12px/1.5 %s;color:#4a5568;word-break:break-all">%s</div>
      </td></tr>`, font, e(grp.title), len(list), font, rows.String())
	}
}

// wrapNames joins names with ", " into lines of at most width characters.
func wrapNames(names []string, width int) []string {
	var lines []string
	cur := ""
	for i, n := range names {
		piece := n
		if i < len(names)-1 {
			piece += ","
		}
		switch {
		case cur == "":
			cur = piece
		case len(cur)+1+len(piece) > width:
			lines = append(lines, cur)
			cur = piece
		default:
			cur += " " + piece
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
