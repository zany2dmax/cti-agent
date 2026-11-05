package appscan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// WHERE THE OWNERS COME FROM
//
// Two sources, one shape:
//
//   - owners.db, the SQLite database fleet-owners keeps. Go has no SQLite
//     driver in its standard library and this module takes no dependencies
//     (SECURITY.md, Supply chain), so Go never opens it: fleet-owners
//     rewrites a JSON snapshot, owners.json, after every change, and that is
//     what is read here.
//   - app-owners.txt, the hand-edited file it replaces.
//
// The snapshot wins whenever it, or owners.db, exists. The file is read only
// while there is neither, so moving to the database is: import, check, done -
// and a snapshot that is missing beside owners.db, cannot be read, or is not
// root's alone is an error, never a quiet fall back to the file. The owners
// decide who receives vulnerability reports; guessing which list applies is
// not an option. Both paths are fixed, not settings: fleet-owners writes
// exactly these, and a variable that moved one would only ever point the
// lanes at a snapshot nothing writes.
//
// Both go through Owners.add, so an entry the file would refuse is refused
// from the snapshot too.

// OwnerSource is somewhere application owners can be read from. A CMDB or an
// identity group would be a third implementation.
type OwnerSource interface {
	// Name says where the owners came from, for messages.
	Name() string
	// Load reads them. Problems are entries it could not use; an error
	// means the source exists and could not be read, and nothing that
	// depends on owners should proceed.
	Load() (Owners, []string, error)
}

// FileOwners is app-owners.txt.
type FileOwners struct{ Path string }

// Name implements OwnerSource.
func (f FileOwners) Name() string { return f.Path }

// Load implements OwnerSource. A missing file is no owners and a problem,
// not an error, as it always was.
func (f FileOwners) Load() (Owners, []string, error) {
	o, p := LoadOwners(f.Path)
	return o, p, nil
}

// SnapshotOwners is owners.json, written by fleet-owners from owners.db.
type SnapshotOwners struct{ Path string }

// Name implements OwnerSource.
func (s SnapshotOwners) Name() string { return s.Path + " (from owners.db)" }

// maxSnapshot bounds owners.json. A few hundred applications are a few tens
// of kilobytes.
const maxSnapshot = 8 << 20

// Load implements OwnerSource.
func (s SnapshotOwners) Load() (Owners, []string, error) {
	st, err := os.Lstat(s.Path)
	if os.IsNotExist(err) {
		return Owners{}, nil, fmt.Errorf("%s is missing but owners.db exists - run "+
			"'sudo cti-agent fleet-owners snapshot'; nothing falls back to app-owners.txt", s.Path)
	}
	if err != nil {
		return Owners{}, nil, err
	}
	if !st.Mode().IsRegular() {
		return Owners{}, nil, fmt.Errorf("%s is not a regular file", s.Path)
	}
	if err := rootOnly(s.Path, st); err != nil {
		return Owners{}, nil, err
	}
	if dst, err := os.Stat(filepath.Dir(s.Path)); err != nil {
		return Owners{}, nil, err
	} else if err := rootOnly(filepath.Dir(s.Path), dst); err != nil {
		return Owners{}, nil, err
	}
	f, err := os.Open(s.Path) // #nosec G304 G703 -- operator config path from fleet.env or the default
	if err != nil {
		return Owners{}, nil, err
	}
	defer func() { _ = f.Close() }()
	o, p, err := ParseOwnersSnapshot(io.LimitReader(f, maxSnapshot+1))
	if err != nil {
		return Owners{}, nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	return o, p, nil
}

// trustedUID owns the snapshot and its directory: root, which is who
// fleet-owners runs as. A variable so the tests can be the owner.
var trustedUID uint32

// rootOnly refuses a file or directory that is not trustedUID's, or that its
// group or anyone else could write: whoever could would choose the recipients.
func rootOnly(path string, st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot tell who owns it", path)
	}
	if sys.Uid != trustedUID || st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be owned by root and writable by nobody else (it is uid %d, %v) - "+
			"fleet-owners writes it; run 'sudo cti-agent fleet-owners snapshot'", path, sys.Uid, st.Mode().Perm())
	}
	return nil
}

// SnapshotFormat is the snapshot's format tag. A file with any other tag is
// refused: a reader that guesses at a newer layout guesses at recipients.
const SnapshotFormat = "cti-owners/1"

// OwnersSnapshot is owners.json.
type OwnersSnapshot struct {
	Format    string    `json:"format"`
	Generated time.Time `json:"generated"`
	// Change is the id of the last change recorded in owners.db, so a
	// snapshot can be matched to the history that produced it.
	Change         int64          `json:"change"`
	Apps           []SnapshotApp  `json:"apps"`
	Sites          []SnapshotSite `json:"sites"`
	AllowedDomains []string       `json:"allowedDomains"`
}

// SnapshotApp is one application's entry. Owner is empty for an
// application recorded only for its covers=.
type SnapshotApp struct {
	App       string   `json:"app"` // "id:123" or the scanner's name
	Owner     string   `json:"owner"`
	Component string   `json:"component,omitempty"`
	Watchers  []string `json:"watchers,omitempty"`
	Covers    []string `json:"covers,omitempty"`
}

// SnapshotSite is a live website with no web app yet, and who should set
// its scan up.
type SnapshotSite struct {
	Domain string `json:"domain"`
	Owner  string `json:"owner"`
}

// ParseOwnersSnapshot reads owners.json.
func ParseOwnersSnapshot(r io.Reader) (Owners, []string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Owners{}, nil, err
	}
	if len(b) > maxSnapshot {
		return Owners{}, nil, fmt.Errorf("over %d MB", maxSnapshot>>20)
	}
	var s OwnersSnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Owners{}, nil, fmt.Errorf("not an owners snapshot: %w", err)
	}
	if s.Format != SnapshotFormat {
		return Owners{}, nil, fmt.Errorf("format %q, this build reads %q - rebuild, or rerun fleet-owners snapshot",
			s.Format, SnapshotFormat)
	}
	o := newOwners()
	o.managed = true
	var problems []string
	for i, a := range s.Apps {
		owner := a.Owner
		if strings.TrimSpace(owner) == "" {
			owner = PlaceholderOwner
		}
		f := []string{strings.TrimSpace(a.App), strings.TrimSpace(owner)}
		if c := strings.TrimSpace(a.Component); c != "" {
			lc := strings.ToLower(c)
			if strings.HasPrefix(lc, "covers=") || strings.HasPrefix(lc, "watchers=") {
				problems = append(problems, fmt.Sprintf("owners.db %s: component %q ignored", a.App, c))
			} else {
				f = append(f, c)
			}
		}
		// Each entry is one value. One with a separator in it would come
		// apart in the join below into values nobody entered.
		if c := oneEach(a.Covers); len(c) > 0 {
			f = append(f, "covers="+strings.Join(c, ","))
		}
		if w := oneEach(a.Watchers); len(w) > 0 {
			f = append(f, "watchers="+strings.Join(w, ","))
		}
		if len(a.Covers)+len(a.Watchers) != len(oneEach(a.Covers))+len(oneEach(a.Watchers)) {
			problems = append(problems, fmt.Sprintf("owners.db %s: a watcher or covers entry with a "+
				"separator in it was ignored", a.App))
		}
		problems = append(problems, o.add("owners.db "+a.App, i+1, f)...)
	}
	for i, st := range s.Sites {
		problems = append(problems, o.add("owners.db site:"+st.Domain, len(s.Apps)+i+1,
			[]string{"site:" + strings.TrimSpace(st.Domain), strings.TrimSpace(st.Owner)})...)
	}
	for _, d := range s.AllowedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			o.allow = append(o.allow, d)
		}
	}
	return o, problems, nil
}

// oneEach drops entries that hold a list separator or a space.
func oneEach(vs []string) []string {
	var out []string
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" && !strings.ContainsAny(v, ",; |\t\r\n") {
			out = append(out, v)
		}
	}
	return out
}

// AllowedDomains is the owner lane's domain allowlist when the source keeps
// one (owners.db does; app-owners.txt does not, and OWNER_ALLOW_DOMAINS in
// fleet.env applies). managed is false when the source keeps none.
func (o Owners) AllowedDomains() (domains []string, managed bool) {
	return o.allow, o.managed
}

// ownersDir is where fleet-owners keeps owners.db and writes owners.json. A
// variable for the tests, not a setting (see the top of this file).
var ownersDir = "/etc/cti-agent"

// OwnersSnapshotPath is owners.json.
func OwnersSnapshotPath() string { return filepath.Join(ownersDir, "owners.json") }

// ConfiguredOwnerSource is the snapshot when it or owners.db exists, else
// the file. A database with no snapshot beside it is the snapshot source
// too, and its Load says the snapshot is missing.
func ConfiguredOwnerSource() OwnerSource {
	snap := OwnersSnapshotPath()
	for _, p := range []string{snap, filepath.Join(ownersDir, "owners.db")} {
		if _, err := os.Lstat(p); err == nil || !os.IsNotExist(err) {
			return SnapshotOwners{Path: snap}
		}
	}
	return FileOwners{Path: OwnersPath()}
}

// LoadConfiguredOwners loads ConfiguredOwnerSource, and says so when the old
// file is still lying beside the database it no longer feeds.
func LoadConfiguredOwners() (Owners, OwnerSource, []string, error) {
	src := ConfiguredOwnerSource()
	o, problems, err := src.Load()
	if err != nil {
		return Owners{}, src, nil, err
	}
	if _, ok := src.(SnapshotOwners); ok {
		if _, err := os.Stat(OwnersPath()); err == nil {
			problems = append(problems, fmt.Sprintf("%s is no longer read - owners come from owners.db; "+
				"remove it once fleet-owners check is clean", OwnersPath()))
		}
	}
	return o, src, problems, nil
}
