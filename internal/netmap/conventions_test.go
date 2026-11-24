package netmap

import (
	"strings"
	"testing"
)

// withConventions restores the defaults after a test that changes them.
func withConventions(t *testing.T) {
	t.Helper()
	labels := map[string]bool{}
	for k, v := range roleLabels {
		labels[k] = v
	}
	t.Cleanup(func() { userOctet, roleLabels = DefaultUserOctet, labels })
}

func corpOf(t *testing.T, rows [][]string, location string) string {
	t.Helper()
	corp, _ := SelectCorp(ParseSites(rows), Rules{})
	for _, c := range corp {
		if strings.HasPrefix(c.Location, location) {
			return c.Subnet.Prefix.String()
		}
	}
	return ""
}

func TestTheUserOctetIsASetting(t *testing.T) {
	withConventions(t)
	if n, on := UserOctet(); n != 30 || !on {
		t.Fatalf("default = %d %v", n, on)
	}
	// Eta's "inside" row is picked by the 10.X.30 rule alone.
	if got := corpOf(t, sample, "Eta Site"); got != "10.17.30.0/24" {
		t.Fatalf("default: Eta = %q", got)
	}
	// Off: only a corp row decides, so Eta has none.
	if err := UseSheetConventions("off", ""); err != nil {
		t.Fatal(err)
	}
	if got := corpOf(t, sample, "Eta Site"); got != "" {
		t.Errorf("off: Eta = %q", got)
	}
	if got := corpOf(t, sample, "Alpha Site"); got != "10.1.30.0/24" {
		t.Errorf("off: a corp row is no longer read: %q", got)
	}
	// Another plan's octet.
	forty := [][]string{{"Location", "Network"}, {"Kappa Site - 10.9.0.0/16"},
		{"inside", "10.9.40.0/24"}, {"voice", "10.9.30.0/24"}}
	if err := UseSheetConventions(" 40 ", ""); err != nil {
		t.Fatal(err)
	}
	if got := corpOf(t, forty, "Kappa Site"); got != "10.9.40.0/24" {
		t.Errorf("40: Kappa = %q", got)
	}
	// Blank is the default again.
	if err := UseSheetConventions("", ""); err != nil {
		t.Fatal(err)
	}
	if n, on := UserOctet(); n != 30 || !on {
		t.Errorf("blank = %d %v", n, on)
	}
}

func TestExtraRowLabelsAreNotLocations(t *testing.T) {
	withConventions(t)
	// A label alone on its row, with no network beside it, reads as a new
	// location: so the corp row under it lands in the wrong one.
	rows := [][]string{{"Location", "Network"}, {"Lambda Site - 10.8.0.0/16"},
		{"Employee  LAN"}, {"corp", "10.8.30.0/24"}}
	where := func() string {
		for _, s := range ParseSites(rows) {
			if s.Role == "corp" {
				return s.Location
			}
		}
		return ""
	}
	if got := where(); got != "Employee  LAN" {
		t.Fatalf("default: the corp row is under %q", got)
	}
	if err := UseSheetConventions("", "employee lan, Printers"); err != nil {
		t.Fatal(err)
	}
	if got := where(); got != "Lambda Site - 10.8.0.0/16" {
		t.Errorf("with the extra label: the corp row is under %q", got)
	}
}

func TestBadConventionsAreRefusedAndChangeNothing(t *testing.T) {
	withConventions(t)
	for _, c := range [][2]string{{"256", ""}, {"-1", ""}, {"thirty", ""}, {"", "corp,<script>"}, {"", strings.Repeat("x", 41)}} {
		if err := UseSheetConventions(c[0], c[1]); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
	if n, on := UserOctet(); n != 30 || !on || roleLabels["<script>"] {
		t.Errorf("a refused setting changed something: %d %v", n, on)
	}
}
