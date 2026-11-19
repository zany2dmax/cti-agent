package statefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type doc struct {
	N    int    `json:"n"`
	Name string `json:"name"`
}

func TestWriteThenReadRoundTripsAt0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "state.json")
	if err := Write(p, doc{N: 3, Name: "x"}, Options{}); err != nil {
		t.Fatal(err)
	}
	var got doc
	if err := Read(p, &got, Options{}); err != nil || got != (doc{3, "x"}) {
		t.Fatalf("%v %+v", err, got)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Dir(p)); di.Mode().Perm() != 0o750 {
		t.Errorf("created dir mode %v, want 0750", di.Mode().Perm())
	}
}

func TestARefusedWriteLeavesTheOldFileAndNoTempFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := Write(p, doc{N: 1}, Options{}); err != nil {
		t.Fatal(err)
	}
	bad := Options{Validate: func() error { return errors.New("n must be positive") }}
	err := Write(p, doc{N: -1}, bad)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "n must be positive") {
		t.Fatalf("err = %v", err)
	}
	var got doc
	_ = Read(p, &got, Options{})
	if got.N != 1 {
		t.Errorf("the old file was changed: %+v", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
}

func TestWriteRefusesAnOversizedValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	err := Write(p, doc{Name: strings.Repeat("x", 500)}, Options{MaxBytes: 100})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(p); serr == nil {
		t.Error("an oversized value was written")
	}
}

func TestReadCapsWhatItWillLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(p, []byte(`{"name":"`+strings.Repeat("x", 1000)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := Read(p, &d, Options{MaxBytes: 100}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadSaysCorruptAndInvalidApart(t *testing.T) {
	dir := t.TempDir()
	corrupt, wrong := filepath.Join(dir, "c.json"), filepath.Join(dir, "w.json")
	_ = os.WriteFile(corrupt, []byte("{not json"), 0o600)
	_ = os.WriteFile(wrong, []byte(`{"n":-5}`), 0o600)
	var d doc
	if err := Read(corrupt, &d, Options{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("corrupt: %v", err)
	}
	vo := Options{Validate: func() error {
		if d.N < 0 {
			return errors.New("n is negative")
		}
		return nil
	}}
	if err := Read(wrong, &d, vo); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "n is negative") {
		t.Errorf("invalid: %v", err)
	}
}

func TestAMissingFileIsNotExist(t *testing.T) {
	var d doc
	err := Read(filepath.Join(t.TempDir(), "none.json"), &d, Options{})
	if !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteGoesThroughNoSymlinkAtTheTarget(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	_ = os.WriteFile(elsewhere, []byte("keep"), 0o600)
	p := filepath.Join(dir, "state.json")
	if err := os.Symlink(elsewhere, p); err != nil {
		t.Skip("no symlinks here")
	}
	if err := Write(p, doc{N: 1}, Options{}); err != nil {
		t.Fatal(err)
	}
	// rename replaces the link itself; it does not write through it
	if b, _ := os.ReadFile(elsewhere); string(b) != "keep" {
		t.Errorf("wrote through a symlink: %q", b)
	}
	if fi, _ := os.Lstat(p); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the symlink was left in place")
	}
}
