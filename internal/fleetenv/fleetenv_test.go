package fleetenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write puts content in a temp file and returns the path.
func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

// clear removes the given names from the environment now and after the test,
// so one case cannot hand its variables to the next one. t.Setenv will not do
// this job: it only restores what it set itself, and LoadFrom sets things
// behind its back.
func clear(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		_ = os.Unsetenv(n)
		t.Cleanup(func() { _ = os.Unsetenv(n) }) // go 1.23: n is per-iteration
	}
}

func TestLoadFromSetsValuesAndCountsThem(t *testing.T) {
	clear(t, "TEST_FE_A", "TEST_FE_B")
	path := write(t, "TEST_FE_A=one\nTEST_FE_B=two\n")

	if n := LoadFrom(path); n != 2 {
		t.Errorf("LoadFrom set %d variable(s), want 2", n)
	}
	for k, want := range map[string]string{"TEST_FE_A": "one", "TEST_FE_B": "two"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// The bug that made this a package: `sudo cti-agent cti-mailbox` reported
// seven variables missing that were all sitting in fleet.env. The wrapper
// exports only the FLEET_* layout, so the file is the only source. If this
// test fails, that failure is back.
func TestTheSevenVariablesCtiMailboxReportedMissingAreAllRead(t *testing.T) {
	names := []string{
		"TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "GRAPH_MAILBOX",
		"QUALYS_BASE_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD",
	}
	clear(t, names...)

	var b strings.Builder
	b.WriteString("# fleet.env, as the installer writes it\n")
	for _, n := range names {
		b.WriteString(n + "=value-of-" + n + "\n")
	}
	if n := LoadFrom(write(t, b.String())); n != len(names) {
		t.Errorf("set %d of %d variables", n, len(names))
	}
	for _, n := range names {
		if got := os.Getenv(n); got != "value-of-"+n {
			t.Errorf("%s = %q, want %q -- this is the cti-mailbox failure", n, got, "value-of-"+n)
		}
	}
}

// `export KEY=value` is a natural thing to write in a file that looks like
// shell, and run-digest/run-patchtuesday do source it as shell, so it is
// valid there. The old Go parser produced a variable named "export KEY", and
// the real name stayed empty -- a config file that reads fine to a human and
// silently supplies nothing.
func TestExportPrefixIsStripped(t *testing.T) {
	clear(t, "TEST_FE_EXPORTED", "export TEST_FE_EXPORTED")
	path := write(t, "export TEST_FE_EXPORTED=yes\n")

	if n := LoadFrom(path); n != 1 {
		t.Fatalf("LoadFrom set %d variable(s), want 1", n)
	}
	if got := os.Getenv("TEST_FE_EXPORTED"); got != "yes" {
		t.Errorf("TEST_FE_EXPORTED = %q, want %q", got, "yes")
	}
	if got := os.Getenv("export TEST_FE_EXPORTED"); got != "" {
		t.Errorf("a variable called %q exists with value %q; the export prefix was not stripped",
			"export TEST_FE_EXPORTED", got)
	}
}

func TestSkipsCommentsBlankLinesAndJunk(t *testing.T) {
	clear(t, "TEST_FE_REAL")
	path := write(t, strings.Join([]string{
		"# a comment",
		"",
		"   ",
		"NOT_AN_ASSIGNMENT",
		"=orphan-value",
		"TEST_FE_REAL=kept",
		"# KEY=commented-out",
	}, "\n"))

	if n := LoadFrom(path); n != 1 {
		t.Errorf("LoadFrom set %d variable(s), want 1 (only TEST_FE_REAL)", n)
	}
	if got := os.Getenv("TEST_FE_REAL"); got != "kept" {
		t.Errorf("TEST_FE_REAL = %q, want %q", got, "kept")
	}
	if got := os.Getenv("KEY"); got == "commented-out" {
		t.Error("a commented-out line was applied")
	}
}

func TestQuotesAreStrippedAndValuesKeepTheirSpacesAndEquals(t *testing.T) {
	clear(t, "TEST_FE_DQ", "TEST_FE_SQ", "TEST_FE_SPACES", "TEST_FE_B64", "TEST_FE_EMPTY")
	path := write(t, strings.Join([]string{
		`TEST_FE_DQ="double"`,
		`TEST_FE_SQ='single'`,
		`TEST_FE_SPACES="a b c"`,
		// A client secret can contain '=' padding. Cut on the first '=' only,
		// or the credential arrives truncated and the only symptom is a 401.
		`TEST_FE_B64=abc==`,
		`TEST_FE_EMPTY=`,
	}, "\n"))

	LoadFrom(path)
	for k, want := range map[string]string{
		"TEST_FE_DQ":     "double",
		"TEST_FE_SQ":     "single",
		"TEST_FE_SPACES": "a b c",
		"TEST_FE_B64":    "abc==",
		"TEST_FE_EMPTY":  "",
	} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// systemd supplies these through EnvironmentFile, and an operator who
// exported something on the command line meant it. The file must never
// overwrite either.
func TestExistingEnvironmentWins(t *testing.T) {
	clear(t, "TEST_FE_PRESET", "TEST_FE_FRESH")
	t.Setenv("TEST_FE_PRESET", "from-systemd")
	path := write(t, "TEST_FE_PRESET=from-file\nTEST_FE_FRESH=from-file\n")

	if n := LoadFrom(path); n != 1 {
		t.Errorf("LoadFrom set %d variable(s), want 1 (the preset one must be skipped)", n)
	}
	if got := os.Getenv("TEST_FE_PRESET"); got != "from-systemd" {
		t.Errorf("TEST_FE_PRESET = %q, want %q -- the file overrode the environment", got, "from-systemd")
	}
	if got := os.Getenv("TEST_FE_FRESH"); got != "from-file" {
		t.Errorf("TEST_FE_FRESH = %q, want %q", got, "from-file")
	}
}

// An empty value already in the environment still counts as set. Otherwise a
// variable deliberately blanked out would be quietly refilled from the file.
func TestAnEmptyExistingValueStillWins(t *testing.T) {
	clear(t, "TEST_FE_BLANKED")
	t.Setenv("TEST_FE_BLANKED", "")
	path := write(t, "TEST_FE_BLANKED=from-file\n")

	if n := LoadFrom(path); n != 0 {
		t.Errorf("LoadFrom set %d variable(s), want 0", n)
	}
	if got := os.Getenv("TEST_FE_BLANKED"); got != "" {
		t.Errorf("TEST_FE_BLANKED = %q, want empty", got)
	}
}

// Under systemd the values are already present and the file may not be
// readable by this process at all. Returning 0 rather than failing is what
// keeps the working path working.
func TestMissingFileIsNotAnError(t *testing.T) {
	if n := LoadFrom(filepath.Join(t.TempDir(), "absent.env")); n != 0 {
		t.Errorf("LoadFrom on a missing file set %d variable(s), want 0", n)
	}
	if n := LoadFrom(t.TempDir()); n != 0 { // a directory, not a file
		t.Errorf("LoadFrom on a directory set %d variable(s), want 0", n)
	}
}

func TestPathPrefersFleetEnvThenFleetHomeThenDefault(t *testing.T) {
	cases := []struct {
		name           string
		fleetEnv, home string
		want           string
	}{
		{"FLEET_ENV wins outright", "/etc/cti/custom.env", "/var/lib/cti-agent", "/etc/cti/custom.env"},
		{"FLEET_ENV wins even with no FLEET_HOME", "/etc/cti/custom.env", "", "/etc/cti/custom.env"},
		{"fleet.env under FLEET_HOME", "", "/home/jleggett/fleet", "/home/jleggett/fleet/fleet.env"},
		{"the Fedora default", "", "", DefaultHome + "/fleet.env"},
		// The wrapper exports FLEET_HOME unconditionally, so an unset value
		// arrives as the empty string rather than absent. Treating that as a
		// real home yields "/fleet.env" at the filesystem root.
		{"whitespace-only is not a home", "", "   ", DefaultHome + "/fleet.env"},
		{"whitespace-only FLEET_ENV falls through", "  ", "/home/jleggett/fleet", "/home/jleggett/fleet/fleet.env"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("FLEET_ENV", c.fleetEnv)
			t.Setenv("FLEET_HOME", c.home)
			if got := Path(); got != c.want {
				t.Errorf("Path() = %q, want %q (FLEET_ENV=%q FLEET_HOME=%q)",
					got, c.want, c.fleetEnv, c.home)
			}
		})
	}
}

func TestLoadReadsThePathPathReports(t *testing.T) {
	clear(t, "TEST_FE_VIA_LOAD")
	path := write(t, "TEST_FE_VIA_LOAD=found\n")
	t.Setenv("FLEET_ENV", path)

	if got := Path(); got != path {
		t.Fatalf("Path() = %q, want %q", got, path)
	}
	if n := Load(); n != 1 {
		t.Fatalf("Load() set %d variable(s), want 1", n)
	}
	if got := os.Getenv("TEST_FE_VIA_LOAD"); got != "found" {
		t.Errorf("TEST_FE_VIA_LOAD = %q, want %q; Load() did not read %s", got, "found", path)
	}
}
