package useragent

import "testing"

func TestBuild(t *testing.T) {
	cases := []struct {
		name, product, override, contact, want string
	}{
		{"contact appended", "cti-x/1.0", "", "fleet@example.com",
			"cti-x/1.0 (+mailto:fleet@example.com)"},
		{"override replaces product", "cti-x/1.0", "cti-agent-fleet/1.0", "fleet@example.com",
			"cti-agent-fleet/1.0 (+mailto:fleet@example.com)"},
		{"no mailbox, no comment", "cti-x/1.0", "", "", "cti-x/1.0"},
		{"operator's own comment kept", "cti-x/1.0", "acme/2 (+https://acme.example)", "fleet@example.com",
			"acme/2 (+https://acme.example)"},
		{"malformed mailbox ignored", "cti-x/1.0", "", "fleet@example.com) evil (", "cti-x/1.0"},
		{"line break in mailbox ignored", "cti-x/1.0", "", "fleet@example.com\r\nX-Evil: 1", "cti-x/1.0"},
		{"line break in override ignored", "cti-x/1.0", "a\r\nX-Evil: 1", "", "cti-x/1.0"},
		{"whitespace trimmed", "cti-x/1.0", "  ", " fleet@example.com ",
			"cti-x/1.0 (+mailto:fleet@example.com)"},
	}
	for _, c := range cases {
		if got := Build(c.product, c.override, c.contact); got != c.want {
			t.Errorf("%s: Build(%q, %q, %q) = %q, want %q",
				c.name, c.product, c.override, c.contact, got, c.want)
		}
	}
}

func TestStringReadsEnvironment(t *testing.T) {
	t.Setenv("FLEET_USER_AGENT", "")
	t.Setenv("GRAPH_MAILBOX", "fleet@example.com")
	if got, want := String("cti-x/1.0"), "cti-x/1.0 (+mailto:fleet@example.com)"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}
