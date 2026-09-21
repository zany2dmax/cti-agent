// Package fleetenv loads fleet.env so a command run by hand has the same
// settings systemd gives it.
//
// # WHY THIS EXISTS AS A PACKAGE
//
// The cti-agent wrapper installed at /usr/local/bin/cti-agent exports only the
// layout - FLEET_HOME, FLEET_CODE, FLEET_ENV, FLEET_FEEDS, HOME - and never
// sources fleet.env. Under systemd the credentials arrive through
// EnvironmentFile, so nothing noticed: run-digest and run-patchtuesday source
// the file themselves in shell, mailer.py reads it in Python, and cti-alert
// had its own copy of this logic in Go.
//
// cti-mailbox did not, so `sudo cti-agent cti-mailbox` - the command the
// runbook tells you to use for the dry run - failed with seven variables
// "missing" that were sitting in fleet.env all along. Four implementations of
// the same idea, and the fifth thing to need it got it wrong.
//
// Existing environment always wins, so systemd's EnvironmentFile and an
// operator's explicit override both take precedence over the file.
package fleetenv

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultHome is where the Fedora layout keeps state, used only to locate
// fleet.env when FLEET_ENV is unset.
const DefaultHome = "/var/lib/cti-agent"

// Path returns the fleet.env location: FLEET_ENV if set, else fleet.env under
// FLEET_HOME, else under DefaultHome.
func Path() string {
	if p := strings.TrimSpace(os.Getenv("FLEET_ENV")); p != "" {
		return p
	}
	home := strings.TrimSpace(os.Getenv("FLEET_HOME"))
	if home == "" {
		home = DefaultHome
	}
	return filepath.Join(home, "fleet.env")
}

// Load reads fleet.env into the environment and reports how many variables it
// set.
//
// A missing or unreadable file is not an error: under systemd the values are
// already present and this call is a no-op, and a command that refused to run
// without the file would break the path that works. The caller's own config
// validation is what reports a genuinely missing setting, by name.
func Load() int {
	return LoadFrom(Path())
}

// LoadFrom reads a specific file. Separated so it is testable without
// reaching into the environment.
func LoadFrom(path string) int {
	// #nosec G304,G703 -- path is FLEET_ENV, or fleet.env under FLEET_HOME.
	// Both are service configuration, and the file holds the credentials the
	// calling process needs, so reading it is the point. The taint flow from
	// os.Getenv is real and crosses no privilege boundary: anyone who can set
	// FLEET_ENV in this process's environment can already run code as this
	// user. Deliberately not "fixed" with filepath.Clean, which normalises
	// ".." and restricts nothing - a control that looks like one and is not.
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// `export KEY=value` is a natural thing to write in a file that looks
		// like shell, and the old parser silently produced a variable called
		// "export KEY".
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		// Existing environment wins: systemd's EnvironmentFile has already
		// run, and an operator who exported something on the command line
		// meant it.
		if _, set := os.LookupEnv(k); !set {
			if os.Setenv(k, v) == nil {
				n++
			}
		}
	}
	return n
}
