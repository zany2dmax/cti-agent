package jira

import (
	"fmt"
	"strings"
	"testing"
)

// hostsN is n host names, so the count is a measurement, not a floor.
func hostsN(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("host-%03d", i)
	}
	return out
}

const cr26125 = "CVE-2026-114938 - java-17-amazon-corretto (Amazon Linux), java-27-amazon-corretto (Amazon Linux), " +
	"java-21-amazon-corretto (Amazon Linux) - 106 hosts, QDS 95"

func javaNow() Finding {
	return Finding{CVE: "CVE-2026-114938", HostCount: 241, Hosts: hostsN(241), Product: "Oracle Java SE, Amazon Corretto +3 more",
		ProductSource: "Qualys"}
}

// CR-26125: filed with three Amazon Linux package names and 106 hosts; the
// comment three days later said 241 hosts. The title follows: the products on
// our hosts and today's count, the QDS flag kept.
func TestRetitleFollowsTheComment(t *testing.T) {
	got, why := Retitle(cr26125, nil, javaNow())
	want := "CVE-2026-114938 - Oracle Java SE, Amazon Corretto +3 more - 241 hosts, QDS 95"
	if got != want {
		t.Fatalf("Retitle = %q (%s), want %q", got, why, want)
	}
	// The stored title is the fleet's own: retitled again.
	prev := &ExposureState{Summary: got, ProductSource: "Qualys"}
	f := javaNow()
	f.HostCount, f.Hosts = 1, hostsN(1)
	if got2, _ := Retitle(got, prev, f); !strings.HasSuffix(got2, " - 1 host, QDS 95") {
		t.Errorf("second retitle = %q", got2)
	}
}

func TestRetitleLeavesAPersonsTitleAlone(t *testing.T) {
	prev := &ExposureState{Summary: cr26125}
	edited := "CVE-2026-114938 - Java runtime on servers and workstations - 106 hosts, QDS 95"
	if got, why := Retitle(edited, prev, javaNow()); got != "" || !strings.Contains(why, "changed in Jira") {
		t.Errorf("a renamed ticket was retitled: %q (%s)", got, why)
	}
	// Not in the fleet's shape at all (and no stored title): left alone.
	if got, why := Retitle("Java upgrades for the server team", nil, javaNow()); got != "" || !strings.Contains(why, "format") {
		t.Errorf("a free-text title was retitled: %q (%s)", got, why)
	}
}

func TestRetitleKeepsTheBetterProductName(t *testing.T) {
	cur := "[OVERDUE] CVE-2026-1234 - Google Chrome - 12 hosts, CISA KEV - Chrome Type Confusion"
	prev := &ExposureState{Summary: cur, ProductSource: "CISA KEV"}
	f := Finding{CVE: "CVE-2026-1234", HostCount: 30, Hosts: hostsN(30), Product: "Google Chrome (Windows)", ProductSource: "Qualys"}
	got, _ := Retitle(cur, prev, f)
	want := "[OVERDUE] CVE-2026-1234 - Google Chrome - 30 hosts, CISA KEV - Chrome Type Confusion"
	if got != want {
		t.Errorf("Retitle = %q, want the KEV name kept and the rest kept: %q", got, want)
	}
	// No product known now: the old one stays; a floor count says so.
	f = Finding{CVE: "CVE-2026-1234", HostCount: 40, CountIsFloor: true}
	if got, _ := Retitle(cur, prev, f); !strings.Contains(got, "Google Chrome - at least 40 hosts") {
		t.Errorf("Retitle = %q", got)
	}
	// A title with no product gains one.
	bare := "CVE-2026-9999 - 1 host, QDS 92"
	f = Finding{CVE: "CVE-2026-9999", HostCount: 2, Hosts: hostsN(2), Product: "PHP", ProductSource: "NVD"}
	if got, _ := Retitle(bare, nil, f); got != "CVE-2026-9999 - PHP - 2 hosts, QDS 92" {
		t.Errorf("Retitle = %q", got)
	}
	// Nothing to change.
	if got, why := Retitle(bare, nil, Finding{CVE: "CVE-2026-9999", HostCount: 1, Hosts: hostsN(1)}); got != "" || !strings.Contains(why, "current") {
		t.Errorf("Retitle = %q (%s)", got, why)
	}
}

// Summary and the retitle write the host count the same way.
func TestSummaryAndRetitleAgreeOnTheCount(t *testing.T) {
	f := Finding{CVE: "CVE-2026-5555", HostCount: 7, CountIsFloor: true, Product: "Foo", ProductSource: "NVD"}
	s := Summary(f, javaNow().FirstSeen)
	if got, why := Retitle(s, &ExposureState{Summary: s, ProductSource: "NVD"}, f); got != "" {
		t.Errorf("a fresh summary was retitled: %q -> %q (%s)", s, got, why)
	}
}
