// Package layout is where the fleet is installed: its code, config, state and
// log directories, and the account it runs as.
//
// The defaults are the FHS layout every box has used. A fork that installs
// elsewhere sets them in layout.env at the top of its repository
// (docs/layout.md); install-fedora.sh then stamps them into every binary at
// build time, the way it stamps the version:
//
//	go build -ldflags "-X .../internal/layout.CodeDir=/srv/fleet ..."
//
// They are variables only so -X can set them. Nothing assigns them at run
// time, and nothing else in the Go code names one of these paths: a test fails
// when a literal path appears outside this file.
package layout

import "path/filepath"

var (
	// CodeDir is the code: binaries, runners, the orchestrator's files.
	CodeDir = "/opt/cti-agent"
	// ConfDir is the config: fleet.env or fleet.d, domains.txt, the org pack.
	ConfDir = "/etc/cti-agent"
	// StateDir is the service account's state: memory.db, reports, traces.
	StateDir = "/var/lib/cti-agent"
	// LogDir is the audit trail (cti-audit(1)).
	LogDir = "/var/log/cti-agent"
	// User is the account the lanes run as.
	User = "ctiagent"
)

// Conf is a file in the config directory.
func Conf(name string) string { return filepath.Join(ConfDir, name) }

// Bin is a program in the code directory's bin/.
func Bin(name string) string { return filepath.Join(CodeDir, "bin", name) }
