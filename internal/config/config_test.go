package config

import (
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	graphVars  = []string{"TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "GRAPH_MAILBOX"}
	qualysVars = []string{"QUALYS_BASE_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD"}
)

// blank clears every variable load() reads, so a test sees the same
// environment whether or not the developer has fleet.env exported in their
// shell. Without this, "is TENANT_ID reported missing?" answers differently
// on the prod box than on a laptop.
func blank(t *testing.T) {
	t.Helper()
	for _, k := range append(append([]string{}, graphVars...), qualysVars...) {
		t.Setenv(k, "")
	}
	t.Setenv("LOOKUP_PROVIDER", "")
	t.Setenv("GRAPH_LOOKBACK_HOURS", "")
	t.Setenv("QUALYS_KB_MAX_AGE_HOURS", "")
}

func set(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		t.Setenv(n, "value-of-"+n)
	}
}

// missingNames pulls the variable names back out of the error. The message is
// the whole user interface of this function: an operator reads that list and
// goes looking in fleet.env, so the list is what is worth asserting on.
func missingNames(t *testing.T, err error) []string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error naming the missing variables, got nil")
	}
	const prefix = "missing required environment variables: ["
	msg := err.Error()
	i := strings.Index(msg, prefix)
	if i < 0 {
		t.Fatalf("error does not look like a missing-variable report: %v", err)
	}
	inner := strings.TrimSuffix(msg[i+len(prefix):], "]")
	if strings.TrimSpace(inner) == "" {
		return nil
	}
	return strings.Fields(inner)
}

func assertSameSet(t *testing.T, got, want []string, context string) {
	t.Helper()
	g, w := append([]string{}, got...), append([]string{}, want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, " ") != strings.Join(w, " ") {
		t.Errorf("%s\n  reported missing: %v\n  should have been:  %v", context, g, w)
	}
}

// Every loader, every combination of what is present, in one table. The point
// of the three entry points is that a command fails on the credentials it
// needs and no others -- twice now a lane has refused to run over settings it
// never reads, and both times the operator went looking in the wrong file.
func TestEachLoaderAsksOnlyForWhatItsCommandUses(t *testing.T) {
	cases := []struct {
		name    string
		load    func() (Config, error)
		present []string
		missing []string
	}{
		{"Load with nothing set wants all seven", Load, nil,
			append(append([]string{}, graphVars...), qualysVars...)},
		{"Load with only Graph still wants Qualys", Load, graphVars, qualysVars},
		{"Load with only Qualys still wants Graph", Load, qualysVars, graphVars},
		{"Load satisfied", Load, append(append([]string{}, graphVars...), qualysVars...), nil},

		// cti-patchtuesday. It correlates against Host Detection and hands its
		// output to mailer.py; it never opens a mailbox.
		{"LoadVulnLookup wants Qualys only", LoadVulnLookup, nil, qualysVars},
		{"LoadVulnLookup runs on Qualys alone, no Graph", LoadVulnLookup, qualysVars, nil},

		// cti-mailbox. It reads the inbox and moves messages; it never asks the
		// scanner anything. This is the run that failed on a box with a
		// complete fleet.env, naming three variables it has no use for.
		{"LoadGraphOnly wants Graph only", LoadGraphOnly, nil, graphVars},
		{"LoadGraphOnly runs on Graph alone, no Qualys", LoadGraphOnly, graphVars, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blank(t)
			set(t, c.present...)

			cfg, err := c.load()
			if len(c.missing) == 0 {
				if err != nil {
					t.Fatalf("want success with %v set, got: %v", c.present, err)
				}
				return
			}
			assertSameSet(t, missingNames(t, err), c.missing,
				"with "+strings.Join(c.present, ",")+" set:")
			if cfg != (Config{}) {
				t.Error("a failed load returned a partly-populated Config; " +
					"a caller that ignores the error would run on it")
			}
		})
	}
}

// The names come out of a map, so an unsorted list printed a different order
// on each run and made one misconfiguration look like several faults.
func TestTheMissingListIsSorted(t *testing.T) {
	blank(t)
	_, err := Load()
	got := missingNames(t, err)
	want := append([]string{}, got...)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("missing list is not sorted:\n  got  %v\n  want %v", got, want)
	}
}

// LOOKUP_PROVIDER is how a deployment turns Qualys off. If the requirement
// did not follow the provider, setting it to "none" would still demand three
// credentials for a scanner nothing is going to call.
func TestANonQualysProviderNeedsNoQualysCredentials(t *testing.T) {
	blank(t)
	set(t, graphVars...)
	t.Setenv("LOOKUP_PROVIDER", "none")

	if _, err := Load(); err != nil {
		t.Errorf("LOOKUP_PROVIDER=none should not require Qualys credentials: %v", err)
	}
}

func TestDefaultsAndDurations(t *testing.T) {
	blank(t)
	set(t, graphVars...)
	set(t, qualysVars...)
	t.Setenv("GRAPH_LOOKBACK_HOURS", "6")
	t.Setenv("QUALYS_KB_MAX_AGE_HOURS", "48")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GraphLookback != 6*time.Hour {
		t.Errorf("GraphLookback = %v, want 6h", cfg.GraphLookback)
	}
	if cfg.QualysKBMaxAge != 48*time.Hour {
		t.Errorf("QualysKBMaxAge = %v, want 48h", cfg.QualysKBMaxAge)
	}
	if cfg.GraphFolder != "inbox" {
		t.Errorf("GraphFolder = %q, want %q", cfg.GraphFolder, "inbox")
	}
	if cfg.LookupProvider != "qualys" {
		t.Errorf("LookupProvider = %q, want %q", cfg.LookupProvider, "qualys")
	}
}

// A zero or unparseable window is not a small window; it is a lane that reads
// nothing and reports no error. Both hour settings have to refuse it.
func TestBadHourSettingsAreRefused(t *testing.T) {
	for _, key := range []string{"GRAPH_LOOKBACK_HOURS", "QUALYS_KB_MAX_AGE_HOURS"} {
		for _, bad := range []string{"0", "-1", "abc", "24h", "1.5"} {
			t.Run(key+"="+bad, func(t *testing.T) {
				blank(t)
				set(t, graphVars...)
				set(t, qualysVars...)
				t.Setenv(key, bad)

				if _, err := Load(); err == nil {
					t.Errorf("%s=%q was accepted", key, bad)
				} else if !strings.Contains(err.Error(), key) {
					t.Errorf("%s=%q was refused, but the error does not name it: %v",
						key, bad, err)
				}
			})
		}
	}
}

// No default mail recipient, ever. A hardcoded fallback here once shipped one
// organisation's internal distribution list as every other deployment's
// default, and an unconfigured install read that mailbox instead of refusing
// to start.
func TestGraphMailboxHasNoDefault(t *testing.T) {
	blank(t)
	set(t, "TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")
	set(t, qualysVars...)

	cfg, err := Load()
	if err == nil {
		t.Fatalf("Load succeeded with no GRAPH_MAILBOX and defaulted it to %q", cfg.GraphMailbox)
	}
	assertSameSet(t, missingNames(t, err), []string{"GRAPH_MAILBOX"},
		"with everything but GRAPH_MAILBOX set:")
}
