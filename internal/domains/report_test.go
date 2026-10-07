package domains

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	rep := Report{
		Now:       now,
		Registrar: "godaddy",
		Results: []Result{
			{Entry: Entry{Name: "example.com", Sends: true},
				Web: []Web{{Host: "example.com", Addrs: Lookup{Values: []string{"192.0.2.1"}},
					HTTPS: Fetch{Tried: true, Status: 200}}},
				Mail: Mail{SPF: Lookup{Values: []string{"v=spf1 -all"}}, DMARC: Lookup{Absent: true},
					DMARCFrom: "example.com", MX: Lookup{Values: []string{"mx.example-mail.test"}}}},
			{Entry: Entry{Name: "example.net"}, Web: []Web{{Host: "example.net", Addrs: Lookup{Absent: true}}}},
		},
		Findings: []Finding{
			{Domain: "example.com", Sev: High, Area: "mail", Text: "no DMARC <record>"},
			{Domain: "example.net", Sev: Medium, Area: "mail", Text: "no SPF"},
		},
		Changes: []Finding{{Domain: "example.com", Sev: Medium, Area: "change", Text: "MX changed"}},
	}
	b := rep.Render()
	if b.Subject != "CTI Fleet Domains Oct 12: 1 High - 2 Medium across 2 domains" {
		t.Errorf("subject = %q", b.Subject)
	}
	for _, s := range []string{"NEEDS ACTION (1)", "CHANGED SINCE LAST WEEK (1)", "REVIEW (1)",
		"INVENTORY (2 domains, 1 live)", "NOT CHECKED", "DMARC none", "apex live", "apex no DNS"} {
		if !strings.Contains(b.Text, s) {
			t.Errorf("text missing %q:\n%s", s, b.Text)
		}
	}
	if strings.Contains(b.HTML, "<record>") || !strings.Contains(b.HTML, "&lt;record&gt;") {
		t.Error("finding text not escaped in HTML")
	}
	if strings.Contains(b.HTML, "<a ") {
		t.Error("the domains report must not contain links")
	}

	rep.Registrar, rep.RegistrarErr = "", "HTTP 401"
	if s := rep.Render().Subject; !strings.Contains(s, "[REGISTRAR NOT CHECKED]") {
		t.Errorf("registrar failure not in subject: %q", s)
	}
	if !strings.Contains(rep.Render().Text, "it failed: HTTP 401") {
		t.Error("registrar failure reason not in the lead")
	}
}
