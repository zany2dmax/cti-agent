// Package statefile is how the fleet's Go commands read and write their own
// JSON state: the budget ledger, the processed-message log, the owners lane's
// delivered log.
//
// # WHY ONE WRITER
//
// Each of those files used to be written by its own copy of "marshal, temp
// file, rename", and none of them checked what it was about to write. The
// state files are small and written only by our own commands, so the risk is
// not an attacker at the keyboard; it is a bug, a corrupt read or a hostile
// value that rides in from outside (a message ID, a subject, a status string
// from a script) and then steers a later run. A budget ledger with a cooldown
// in the year 9999 stops the heartbeat for good; a processed log with an entry
// dated next year is never pruned and makes mail eligible to move on a record
// that never expires. Validation belongs at the write, where the bad value can
// still be refused, and at the read, where a file that was damaged or edited
// is noticed before it is trusted.
//
// # WHAT IT DOES
//
// Write validates the value, marshals it, refuses output over a size cap, and
// replaces the file atomically: a temp file in the same directory (mode 0600,
// never a name an attacker can pre-create), flushed to disk, then renamed over
// the target and the directory flushed. A reader sees the old file or the new
// one, never half of one, and a refused write leaves the old file untouched.
//
// Read reads at most the size cap, unmarshals, and validates. A damaged file is
// reported as ErrInvalid so each caller can keep its own policy: the budget
// ledger starts fresh (an outage over a counter is worse), the processed log
// fails closed (the mailbox lane would otherwise silently stop).
package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DefaultMaxBytes is the cap when Options.MaxBytes is zero: far above any real
// state file here (the largest, the processed log, is tens of kilobytes) and far
// below a size that could exhaust memory or disk.
const DefaultMaxBytes = 4 << 20

// ErrInvalid is wrapped by every error that says the content is wrong: it
// would not parse, it failed validation, or it is over the size cap.
var ErrInvalid = errors.New("invalid state")

// Options says how to read or write one state file. The zero value is safe.
type Options struct {
	// MaxBytes caps the file's size, read or written. Zero means DefaultMaxBytes.
	MaxBytes int
	// Validate is run on the value before it is written and after it is read.
	// A non-nil error refuses the write (nothing is touched) or marks the read
	// invalid. Nil means no check beyond the JSON itself.
	Validate func() error
	// DirMode is the mode for a directory that has to be created. Zero means 0750.
	DirMode os.FileMode
}

func (o Options) max() int {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return DefaultMaxBytes
}

// Write validates v, marshals it indented, and replaces path atomically with
// mode 0600. Validation runs first, so a refused write changes nothing.
func Write(path string, v any, o Options) error {
	if o.Validate != nil {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("%w: refusing to write %s: %v", ErrInvalid, filepath.Base(path), err)
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > o.max() {
		return fmt.Errorf("%w: %s would be %d bytes, over the %d byte limit", ErrInvalid, filepath.Base(path), len(b), o.max())
	}
	dir := filepath.Dir(path)
	mode := o.DirMode
	if mode == 0 {
		mode = 0o750
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// Flush the directory entry too, so the rename survives a power cut. Best
	// effort: not every filesystem supports it, and the data is already safe.
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the state directory we just wrote to
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Read reads path into v, reading at most the size cap, and validates it. A
// missing file is reported as an error satisfying os.IsNotExist (errors.Is with
// os.ErrNotExist) so callers can treat it as an empty state. Content that
// is too large, will not parse or fails validation wraps ErrInvalid.
func Read(path string, v any, o Options) error {
	f, err := os.Open(path) // #nosec G304 -- the caller's own state file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, int64(o.max())+1))
	if err != nil {
		return err
	}
	if len(b) > o.max() {
		return fmt.Errorf("%w: %s is over the %d byte limit", ErrInvalid, filepath.Base(path), o.max())
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, filepath.Base(path), err)
	}
	if o.Validate != nil {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalid, filepath.Base(path), err)
		}
	}
	return nil
}
