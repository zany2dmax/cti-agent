package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yourorg/cti-qualys-agent/internal/vulnlookup"
)

// sensitiveHost stands in for the kind of internal FQDN that must never reach a
// committed file. If it appears in redacted output, the redaction is broken.
//
// It uses the RFC 2606 reserved .invalid TLD deliberately: the string is
// obviously synthetic, so a future history-scrub or secret scanner will not
// mistake it for a real asset and rewrite it out from under this test.
const sensitiveHost = "db01.internal.example.invalid"

func sampleResults() []vulnlookup.Result {
	return []vulnlookup.Result{
		{
			CVE:         "CVE-2020-1472",
			Status:      vulnlookup.StatusPresent,
			Source:      "qualys",
			ExternalIDs: []string{"91668", "91680"},
			HostCount:   4,
			MaxScore:    100,
			LastSeen:    "2026-06-03T19:10:28Z",
			SampleHosts: []string{sensitiveHost, "dc01.example.internal", sensitiveHost},
		},
		{
			CVE:         "CVE-2026-0826",
			Status:      vulnlookup.StatusUnknown,
			Source:      "qualys",
			ExternalIDs: nil,
			Reason:      "No Qualys KnowledgeBase CVE-to-QID mapping found",
		},
	}
}

func writeToTemp(t *testing.T, mode, salt string) string {
	t.Helper()
	t.Setenv("REPORT_HOSTNAMES", mode)
	t.Setenv("REPORT_REDACTION_SALT", salt)

	path := filepath.Join(t.TempDir(), "report.md")
	err := WriteMarkdown(path, "cybersecurity@example.com", time.Now().Add(-24*time.Hour),
		42, "qualys", sampleResults())
	if err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(b)
}

func TestRedactIsDefault(t *testing.T) {
	// An unset REPORT_HOSTNAMES, or any unrecognized value, must redact.
	for _, mode := range []string{"", "nonsense", "REDACT", " redact "} {
		out := writeToTemp(t, mode, "salt")
		if strings.Contains(out, sensitiveHost) {
			t.Errorf("mode %q leaked the real hostname", mode)
		}
		if !strings.Contains(out, "host-") {
			t.Errorf("mode %q produced no pseudonyms", mode)
		}
	}
}

func TestRedactHidesHostnamesButKeepsCounts(t *testing.T) {
	out := writeToTemp(t, "redact", "salt")

	if strings.Contains(out, sensitiveHost) || strings.Contains(out, "internal.example.invalid") {
		t.Error("redacted report still contains the real hostname")
	}
	// Host count is the actionable part and must survive redaction.
	if !strings.Contains(out, "| 4 |") {
		t.Error("host count was lost")
	}
	// Non-hostname reason text must pass through untouched.
	if !strings.Contains(out, "No Qualys KnowledgeBase CVE-to-QID mapping found") {
		t.Error("reason text was mangled")
	}
	if !strings.Contains(out, "Hostname disclosure: `redact`") {
		t.Error("report does not declare its disclosure mode")
	}
}

func TestPseudonymsAreStableAndUnique(t *testing.T) {
	a := pseudonym(sensitiveHost, "salt")
	b := pseudonym(sensitiveHost, "salt")
	if a != b {
		t.Errorf("pseudonym is not stable: %s != %s", a, b)
	}
	if pseudonym("other.example.internal", "salt") == a {
		t.Error("distinct hosts collided")
	}
	// Case and surrounding whitespace must not produce a different label.
	if pseudonym("  DB01.Internal.Example.INVALID  ", "salt") != a {
		t.Error("pseudonym is not normalized for case/whitespace")
	}
	if !strings.HasPrefix(a, "host-") || len(a) != len("host-")+8 {
		t.Errorf("unexpected pseudonym shape: %q", a)
	}
}

func TestSaltChangesPseudonyms(t *testing.T) {
	// This is the whole point of the salt: without it, an attacker holding a
	// candidate hostname can hash it and confirm a match against the report.
	if pseudonym(sensitiveHost, "salt-a") == pseudonym(sensitiveHost, "salt-b") {
		t.Error("salt has no effect on the pseudonym")
	}
	if pseudonym(sensitiveHost, "") == pseudonym(sensitiveHost, "salt") {
		t.Error("unsalted and salted pseudonyms match")
	}
}

func TestUnsaltedRedactionWarns(t *testing.T) {
	out := writeToTemp(t, "redact", "")
	if !strings.Contains(out, "REPORT_REDACTION_SALT") {
		t.Error("no warning when redacting without a salt")
	}
}

func TestRepeatedHostsAreDeduped(t *testing.T) {
	out := writeToTemp(t, "redact", "salt")
	label := pseudonym(sensitiveHost, "salt")
	if n := strings.Count(out, label); n != 1 {
		t.Errorf("pseudonym appears %d times, want 1 (dedupe failed)", n)
	}
}

func TestCountModeWithholdsNames(t *testing.T) {
	out := writeToTemp(t, "count", "salt")
	if strings.Contains(out, sensitiveHost) || strings.Contains(out, "host-") {
		t.Error("count mode disclosed host identifiers")
	}
	if !strings.Contains(out, "3 host(s) - names withheld") {
		t.Error("count mode did not report the number of sample hosts")
	}
}

func TestFullModeDisclosesAndWarns(t *testing.T) {
	out := writeToTemp(t, "full", "salt")
	if !strings.Contains(out, sensitiveHost) {
		t.Error("full mode did not include real hostnames")
	}
	if !strings.Contains(out, "Contains real hostnames") {
		t.Error("full mode is missing the do-not-commit banner")
	}
}

func TestReportIsNotWorldReadable(t *testing.T) {
	t.Setenv("REPORT_HOSTNAMES", "full")
	path := filepath.Join(t.TempDir(), "report.md")
	if err := WriteMarkdown(path, "m@example.com", time.Now(), 1, "qualys", sampleResults()); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("report mode is %#o, want 0600", perm)
	}
}

func TestPipesAreEscaped(t *testing.T) {
	t.Setenv("REPORT_HOSTNAMES", "full")
	path := filepath.Join(t.TempDir(), "report.md")
	res := []vulnlookup.Result{{
		CVE:    "CVE-2026-0001",
		Status: vulnlookup.StatusUnknown,
		Source: "qualys",
		Reason: "weird | reason | with pipes",
	}}
	if err := WriteMarkdown(path, "m@example.com", time.Now(), 1, "qualys", res); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `weird \| reason \| with pipes`) {
		t.Error("pipe characters were not escaped, table will break")
	}
}
