package domains

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

// WHO EACH SPF INCLUDE IS FOR
//
// An SPF record is a list of other people's names, and nobody can read
// "include:_phishspf.knowbe4.com" and say at a glance whether we still use
// KnowBe4. Every one that stays authorises a third party to send mail as the
// domain, so the question the mail admin has to answer is "do we use this
// vendor?" - and cannot answer it from the hostname. This names the vendor and
// says what it does, once per include, with the domains that carry it, so
// "we do not use that vendor" becomes one decision and one removal.
//
// The table is the common senders only, matched by host suffix. An include
// that is not in it is listed as unrecognised, which is the useful case: it is
// the one somebody has to go and find out about. DOMAINS_SPF_VENDORS adds or
// overrides entries (suffix=description, comma separated) so that, once
// somebody has found out, the next report says it.

type spfVendor struct{ suffix, what string }

var spfVendors = []spfVendor{
	{"spf.protection.outlook.com", "Microsoft 365 (Exchange Online) - mail sent from Outlook/Microsoft 365"},
	{"_spf.google.com", "Google Workspace - mail sent from Gmail/Google"},
	{"_phishspf.knowbe4.com", "KnowBe4 - phishing-simulation / security-awareness emails"},
	{"knowbe4.com", "KnowBe4 - phishing-simulation / security-awareness emails"},
	{"spf.smtp2go.com", "SMTP2GO - outbound email-delivery service (applications, devices, scripts)"},
	{"smtp2go.com", "SMTP2GO - outbound email-delivery service (applications, devices, scripts)"},
	{"servers.mcsv.net", "Mailchimp - marketing email"},
	{"mcsv.net", "Mailchimp - marketing email"},
	{"mandrillapp.com", "Mandrill (Mailchimp Transactional) - application email"},
	{"sendgrid.net", "SendGrid (Twilio) - application and marketing email"},
	{"mailgun.org", "Mailgun - application email"},
	{"mtasv.net", "Postmark - application email"},
	{"amazonses.com", "Amazon SES - application email"},
	{"_spf.salesforce.com", "Salesforce - CRM email"},
	{"salesforce.com", "Salesforce - CRM email"},
	{"exacttarget.com", "Salesforce Marketing Cloud - marketing email"},
	{"mktomail.com", "Marketo - marketing email"},
	{"constantcontact.com", "Constant Contact - marketing email"},
	{"sendinblue.com", "Brevo (Sendinblue) - marketing email"},
	{"mailjet.com", "Mailjet - application and marketing email"},
	{"elasticemail.com", "Elastic Email - email-delivery service"},
	{"zendesk.com", "Zendesk - help-desk email"},
	{"_spf.atlassian.net", "Atlassian - Jira/Confluence notification email"},
	{"atlassian.net", "Atlassian - Jira/Confluence notification email"},
	{"spf.messagelabs.com", "Symantec / Broadcom email security"},
	{"mimecast.com", "Mimecast - email security gateway"},
	{"ppe-hosted.com", "Proofpoint Essentials (a different Proofpoint product from on Demand)"},
	{"pphosted.com", "Proofpoint on Demand - our mail gateway"},
	{"secureserver.net", "GoDaddy - hosted email / GoDaddy-sent mail"},
	{"iphmx.com", "Cisco Secure Email"},
	{"barracudanetworks.com", "Barracuda - email security"},
	{"zoho.com", "Zoho Mail"},
}

// extraSPFVendors reads DOMAINS_SPF_VENDORS: "suffix=description,...". A
// description may not contain a comma; entries without "=" are ignored.
func extraSPFVendors() []spfVendor {
	var out []spfVendor
	for _, part := range strings.Split(os.Getenv("DOMAINS_SPF_VENDORS"), ",") {
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if ok && k != "" && v != "" {
			out = append(out, spfVendor{k, v})
		}
	}
	return out
}

// SPFVendor says who an include/redirect target belongs to. known is false
// for a host in neither the built-in table nor DOMAINS_SPF_VENDORS.
func SPFVendor(host string) (what string, known bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	match := func(tbl []spfVendor) (string, bool) {
		for _, v := range tbl {
			if h == v.suffix || strings.HasSuffix(h, "."+v.suffix) {
				return v.what, true
			}
		}
		return "", false
	}
	// The operator's entries win, so a vendor the table describes wrongly or
	// too vaguely can be corrected without a release.
	if w, ok := match(extraSPFVendors()); ok {
		return w, true
	}
	if w, ok := match(spfVendors); ok {
		return w, true
	}
	return "", false
}

// podIPs reads PROOFPOINT_POD_IPS: the Proofpoint on Demand addresses some
// SPF records list directly because adding the include would push them over
// SPF's limit of 10 DNS lookups. Entries are addresses or CIDR ranges,
// separated by commas (spaces are tolerated here, but fleet.env is sourced by
// the shell, where an unquoted space would run the second entry as a command).
// Empty means none.
func podIPs() []netip.Prefix {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(os.Getenv("PROOFPOINT_POD_IPS"),
		func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' }) {
		f = strings.TrimPrefix(strings.ToLower(f), "ip4:")
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p)
		} else if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// isPoDIP reports whether an SPF mechanism ("ip4:148.163.143.101") is one of
// the listed Proofpoint on Demand addresses, or a range inside one.
func isPoDIP(mech string, pod []netip.Prefix) bool {
	m := strings.TrimLeft(strings.ToLower(mech), "+~?-")
	m, ok := strings.CutPrefix(m, "ip4:")
	if !ok {
		return false
	}
	var p netip.Prefix
	if pp, err := netip.ParsePrefix(m); err == nil {
		p = pp
	} else if a, err := netip.ParseAddr(m); err == nil {
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		return false
	}
	for _, listed := range pod {
		if listed.Contains(p.Addr()) && p.Bits() >= listed.Bits() {
			return true
		}
	}
	return false
}

// spfPoDByAddress reports whether any SPF record lists a PoD address.
func spfPoDByAddress(records []string) bool {
	pod := podIPs()
	if len(pod) == 0 {
		return false
	}
	for _, rec := range records {
		for _, t := range strings.Fields(rec) {
			if isPoDIP(t, pod) {
				return true
			}
		}
	}
	return false
}

// SPFInclude is one include (or listed address) with who it is for and every
// domain whose SPF carries it.
type SPFInclude struct {
	Mechanism string // "include:spf.smtp2go.com", or "ip4:148.163.143.101"
	Vendor    string // "" when unrecognised
	Domains   []string
}

// SPFIncludes lists each include/redirect in the domains' own SPF records,
// with its vendor. Only the record's own mechanisms are described, not what a
// vendor's record in turn includes. Unrecognised ones come first (they are
// the ones to find out about), then the most widely used.
func SPFIncludes(results []Result) []SPFInclude {
	pod := podIPs()
	byMech := map[string]*SPFInclude{}
	add := func(mech, vendor, domain string) {
		x := byMech[mech]
		if x == nil {
			x = &SPFInclude{Mechanism: mech, Vendor: vendor}
			byMech[mech] = x
		}
		x.Domains = append(x.Domains, domain)
	}
	for _, r := range results {
		seen := map[string]bool{}
		for _, rec := range r.Mail.SPF.Values {
			for _, tok := range strings.Fields(strings.ToLower(rec)) {
				tok = strings.TrimLeft(tok, "+~?-")
				var mech, host string
				switch {
				case strings.HasPrefix(tok, "include:"):
					mech, host = tok, strings.TrimPrefix(tok, "include:")
				case strings.HasPrefix(tok, "redirect="):
					mech, host = "redirect:"+strings.TrimPrefix(tok, "redirect="), strings.TrimPrefix(tok, "redirect=")
				case isPoDIP(tok, pod):
					if !seen[tok] {
						seen[tok] = true
						add(tok, "Proofpoint on Demand - our mail gateway, listed by address to stay under SPF's 10-lookup limit", r.Entry.Name)
					}
					continue
				default:
					continue
				}
				if seen[mech] {
					continue
				}
				seen[mech] = true
				what, _ := SPFVendor(host)
				add(mech, what, r.Entry.Name)
			}
		}
	}
	out := make([]SPFInclude, 0, len(byMech))
	for _, x := range byMech {
		sort.Strings(x.Domains)
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Vendor == "") != (out[j].Vendor == "") {
			return out[i].Vendor == ""
		}
		if len(out[i].Domains) != len(out[j].Domains) {
			return len(out[i].Domains) > len(out[j].Domains)
		}
		return out[i].Mechanism < out[j].Mechanism
	})
	return out
}

// SPFVendorsTitle heads the report section.
const SPFVendorsTitle = "SPF INCLUDES - WHO EACH ONE IS FOR"

const spfVendorsNote = "Each include lets that sender mail as the domain. If we no longer use the " +
	"vendor, the include can come out of the SPF record. 'Not recognised' means this " +
	"report has no entry for it: find out who owns it before keeping or removing it " +
	"(DOMAINS_SPF_VENDORS records the answer)."

func (x SPFInclude) vendorText() string {
	if x.Vendor == "" {
		return "NOT RECOGNISED - find out who this is"
	}
	return x.Vendor
}

func (x SPFInclude) domainsText(max int) string {
	if len(x.Domains) <= max {
		return strings.Join(x.Domains, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(x.Domains[:max], ", "), len(x.Domains)-max)
}

func (r Report) spfVendorsText(b *strings.Builder) {
	inc := SPFIncludes(r.Results)
	if len(inc) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s (%d)\n%s\n%s\n", SPFVendorsTitle, len(inc),
		strings.Repeat("-", len(SPFVendorsTitle)+5), spfVendorsNote)
	for _, x := range inc {
		fmt.Fprintf(b, "  %s\n      %s\n      on %d domain(s): %s\n",
			x.Mechanism, x.vendorText(), len(x.Domains), x.domainsText(8))
	}
}

func (r Report) spfVendorsHTML(b *strings.Builder) {
	inc := SPFIncludes(r.Results)
	if len(inc) == 0 {
		return
	}
	sectionHTML(b, fmt.Sprintf("%s (%d)", SPFVendorsTitle, len(inc)), emailkit.Blue.Fg)
	itemHTML(b, spfVendorsNote)
	for _, x := range inc {
		tone := emailkit.Blue
		if x.Vendor == "" {
			tone = emailkit.Amber
		}
		colour, bg := tone.Fg, tone.Bg
		fmt.Fprintf(b, `
      <tr><td style="padding:0 0 8px 0">
        <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid %s;background:%s;border-radius:0 4px 4px 0">
          <tr><td style="padding:8px 12px">
            <div style="font:700 13px ui-monospace,Menlo,monospace;color:#1a202c;word-break:break-all">%s</div>
            <div style="font:400 13px/1.5 %s;color:#1a202c">%s</div>
            <div style="font:400 12px/1.5 %s;color:#4a5568">on %d domain(s): %s</div>
          </td></tr></table></td></tr>`,
			colour, bg, e(x.Mechanism), font, e(x.vendorText()), font, len(x.Domains), e(x.domainsText(8)))
	}
}
