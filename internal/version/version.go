// Package version reports what this build actually is.
//
// # WHY THIS EXISTS
//
// install-fedora.sh builds from whatever the checkout happens to be on and,
// until now, never recorded it. That is how a stale checkout installed a
// binary predating a feature while the installer printed "Installed" - the
// box reported success about code it did not have, and the only way to tell
// was to notice a command that should exist and did not.
//
// "What is production running?" has to be answerable by asking production,
// not by inferring it from a laptop's git log.
//
// # WHAT THE FIELDS MEAN
//
// Tag and Commit are injected at build time with -ldflags. A binary built
// without them says so rather than claiming a version it cannot support: a
// confident wrong answer here is worse than an admitted unknown, because the
// whole point is to be trusted during an incident.
package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Injected via -ldflags "-X github.com/zany2dmax/cti-agent/internal/version.Tag=v1.0".
var (
	Tag    = ""
	Commit = ""
	Built  = ""
)

// Unknown is what every field reads when nothing was injected.
const Unknown = "unknown"

// Info is a resolved description of this build.
type Info struct {
	Tag    string
	Commit string
	Built  string
	// Dirty means the working tree had uncommitted changes at build time.
	// Worth surfacing: a binary built from a dirty tree cannot be reproduced
	// from its commit, so "it matches the tag" stops being a useful claim.
	Dirty bool
	// Stamped is false when nothing was injected, which means the binary was
	// built outside the install path - a `go build` by hand, or an older
	// installer. Callers should say so rather than printing "unknown" and
	// letting a reader assume it means something.
	Stamped bool
}

// Get resolves the build information, falling back to what the Go toolchain
// embeds when ldflags were not supplied.
//
// The fallback matters: `go build` records VCS information automatically, so a
// hand-built binary can still name its commit even though the installer did
// not stamp it. That covers the exact case where somebody is debugging on a
// workstation and needs to know what they are running.
func Get() Info {
	i := Info{Tag: Tag, Commit: Commit, Built: Built, Stamped: Tag != "" || Commit != ""}

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.Commit == "" {
					i.Commit = s.Value
				}
			case "vcs.time":
				if i.Built == "" {
					i.Built = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					i.Dirty = true
				}
			}
		}
	}

	if i.Tag == "" {
		i.Tag = Unknown
	}
	if i.Commit == "" {
		i.Commit = Unknown
	}
	if i.Built == "" {
		i.Built = Unknown
	}
	return i
}

// Short is the commit abbreviated for reading, not for identity. Twelve
// characters rather than seven: this repository will outlive the point where
// seven is comfortably unique, and a truncated hash that collides during an
// incident is a bad day.
func (i Info) Short() string {
	if i.Commit == Unknown || len(i.Commit) < 12 {
		return i.Commit
	}
	return i.Commit[:12]
}

// String is the one-line form for logs and --check output.
func (i Info) String() string {
	var b strings.Builder
	b.WriteString(i.Tag)
	b.WriteString(" (")
	b.WriteString(i.Short())
	if i.Dirty {
		// Loud, because a dirty build cannot be reproduced from its commit.
		b.WriteString("-DIRTY")
	}
	b.WriteString(")")
	if i.Built != Unknown {
		b.WriteString(" built ")
		b.WriteString(i.Built)
	}
	if !i.Stamped {
		b.WriteString(" [not stamped by the installer]")
	}
	return b.String()
}

// Mismatch compares this binary against what the installer recorded, and
// explains the difference rather than returning a bare boolean.
//
// The case worth catching: a binary left behind by an older install sitting
// beside newer ones, which is exactly what a partial or failed install
// produces and what no amount of "Installed" output will reveal.
func (i Info) Mismatch(recordedCommit string) string {
	recordedCommit = strings.TrimSpace(recordedCommit)
	if recordedCommit == "" || recordedCommit == Unknown || i.Commit == Unknown {
		return ""
	}
	if !strings.HasPrefix(recordedCommit, i.Commit) && !strings.HasPrefix(i.Commit, recordedCommit) {
		return fmt.Sprintf(
			"this binary is %s but the install recorded %s - it was not replaced "+
				"by the last install, so it predates whatever else was",
			i.Short(), shorten(recordedCommit))
	}
	return ""
}

func shorten(s string) string {
	if len(s) < 12 {
		return s
	}
	return s[:12]
}
